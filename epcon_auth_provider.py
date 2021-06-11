"""
Matrix Synapse Password Provider Based on EuroPython Conference User Auth

This module is a Matrix Synapse password provider that uses the EuroPython
conference website (e.g. ep2021.europython.eu) to authenticate users.

The basic flow is as follows: users authenticate on the EuroPython conference
website (e.g. https://ep2021.europython.eu) and go to their user profile
dashboard (e.g. https://ep2021.europython.eu/user-panel/).

There they will find a section called "EuroPython Conference System". Within
that secion, they will find the vredentials that they will need to use to
login on the EuroPython Matrix installation (https://matrix.europython.eu/).

The login method on the EuroPython Matrix server is email and password. However
this password provider module also accepts an email address as username.

Two configuration directoves are needed to use this password provider (usually
added to your inventory vars.yml):

matrix_synapse_ext_password_provider_epcon_auth_enabled
matrix_synapse_ext_password_provider_epcon_auth_endpoint

Set the first one to `true` to enable this authentication method. False to
disable it.

Set `matrix_synapse_ext_password_provider_epcon_auth_endpoint` to the URL of
the epcon authentication API endpoint. For instance, in 2021 one would use
https://ep2021.europython.eu/api/v1/isauth/
"""
import logging
import bcrypt
import unicodedata

from twisted.internet import defer
from synapse.api.errors import HttpResponseException, SynapseError
from synapse.types import create_requester
from synapse.api.constants import Membership
from synapse.types import UserID, RoomAlias


logger = logging.getLogger(__name__)


# These comne from ep2021
FARE = {
    'combined': ['TRCC', 'TRCP'],
    'conference': ['TRSC', 'TRSP'],
    'sprint': ['TRPC', 'TRPP'],
}


def isspeaker(epcondata):
    return epcondata['is_speaker'] is True


def isadmin(epcondata):
    return epcondata['is_staff'] is True


def isattendee(epcondata):
    for ticket in epcondata["tickets"]:
        if ticket["fare_code"] in FARE['combined'] or FARE['conference']:
            return True
    return False


def issprinter(epcondata):
    # If they got here, they are sprinters :-)
    return True


def everybody(epcondata):
    return True


# We decide these rules
PUBLIC_ROOM_RULES = (everybody, )

ROOM_ACCESS_RULES = {
    "#info-desk": everybody,
    "#hallway": everybody,
    "#announcements": everybody,
    "#staff": isadmin,
    "#speakers": isspeaker,
    "#coc": everybody,
    "#optiver": isattendee,
    "#brian": isattendee,
    "#ni": isattendee,
    "#parrot": isattendee,
    "#silly-walks": isattendee,
    "#argument-clinic": isattendee,
    "#sprints": everybody,
}


class EpconAuthProvider:
    def __init__(self, config, account_handler, room_rules=ROOM_ACCESS_RULES):
        self.account_handler = account_handler
        self.hs = account_handler._hs
        self.http_client = account_handler._http_client
        self.store = self.hs.get_datastore()
        self.bcrypt_rounds = self.hs.config.bcrypt_rounds
        self.server_name = self.hs.config.server_name

        self.room_rules = {f'{room_name}:{self.server_name}': rule
                           for room_name, rule in room_rules.items()}

        if not config.endpoint:
            raise RuntimeError('Missing endpoint config')

        self.endpoint = config.endpoint
        self.admin_user = config.admin_user
        self.config = config
        logger.info('Endpoint: %s', self.endpoint)

    def get_rooms_for_user(self, epcondata):
        """
        Apply the rules for room assignment defined above.

        Remember: room names need to be decorated with homeserver name...
        """
        return {
            room_name for room_name, rule in self.room_rules.items()
            if rule(epcondata)
        }

    async def create_epcon_rooms(self):
        if not await self.account_handler.check_user_exists(self.admin_user):
            logger.info("Not creating default rooms as %s doesn't exists",
                        self.admin_user)
            return

        logger.info("Attempt to create default rooms for EuroPython")
        room_creation_handler = self.hs.get_room_creation_handler()
        create_requester(self.admin_user)

        for room_name, rule in self.room_rules.items():
            public = rule in PUBLIC_ROOM_RULES

            logger.info("Creating %s", room_name)
            try:
                room_alias = RoomAlias.from_string(room_name)
                stub_config = {
                    "preset": "public_chat" if public else "private_chat",
                    "room_alias_name": room_alias.localpart,
                    "creation_content": {"m.federate": False}
                }
                info, _ = await room_creation_handler.create_room(
                    create_requester(self.admin_user),
                    config=stub_config,
                    ratelimit=False,
                )
            except Exception as e:
                logger.error("Failed to create default channel %r: %r",
                             room_name, e)
            else:
                logger.info(f'Created {room_name} as {info}')

    @staticmethod
    def parse_config(config):
        _require_keys(config, ["endpoint", "admin_user"])

        class _RestConfig(object):
            endpoint = ''

        rest_config = _RestConfig()
        rest_config.endpoint = config["endpoint"]
        rest_config.admin_user = config["admin_user"]
        return rest_config

    async def check_3pid_auth(self, medium, address, password):
        """
        Handle authentication against thirdparty login types, such as email
        Args:
            medium (str): Medium of the 3PID (e.g email, msisdn).
            address (str): Address of the 3PID (e.g bob@example.com for email).
            password (str): The provided password of the user.

        Returns:
             user_id (str|None): ID of the user if authentication successful.
             None otherwise.
        """
        # Only e-mail supported email
        if medium != "email":
            logger.debug("Not going to auth medium: %s, address: %s",
                         medium, address)
            return None

        logger.info("Going to check auth for %s", address)

        epcondata = await self.auth_with_epcon(address, password)
        if not epcondata:
            logger.info("Auth failed for %s", address)
            raise SynapseError(code=400, errcode="no_tickets_found",
                               msg='Login failed: auth API error.')

        logger.info("%s successfully authenticated with epcon. profile: %s",
                    address, epcondata)

        # If no tickets found inside epcondata return false.
        tickets = epcondata.get("tickets", None)
        if not tickets:
            logger.info("Auth failed for %s - no tickets found", address)
            raise SynapseError(code=400, errcode="no_tickets_found",
                               msg='Login failed: No tickets found for user.')

        # Create the account in Synapse, if needed.
        user_id = await self.get_or_create_userid(epcondata, password)
        try:
            await self.apply_user_policies(user_id, epcondata)
        except Exception as e:
            logger.error("Error joining rooms :%r", e)
        logger.info("User registered. address: '%s' user_id: '%s'",
                    address, user_id)
        return user_id

    async def apply_user_policies(self, user_id, epcondata):
        """
        Assign the user to the relevant rooms (creating them if needed).

        Some notes:
        * Rooms are created the first time an admin user logs in.
        * Admins in synapse are staff users un epcon.
        * In order to assign users to rooms, we use the rules defined above.
        """
        # If the user is an admin and rooms were not created yet, create them.
        if user_id == self.admin_user:
            await self.create_epcon_rooms()

        # Get the list of rooms the user already belongs to and check against
        # our rules.
        room_hanlder = self.hs.get_room_member_handler()
        # Our user already belongss to the following rooms:
        room_ids = await self.store.get_rooms_for_user(user_id)
        # Our user should be a member of the following rooms:
        rooms_to_join = self.get_rooms_for_user(epcondata)

        # Make sure that the two lists above are not at odds with each other.
        rooms_to_leave = set(room_ids) - set(rooms_to_join)

        # First make sure that we remove user from rooms_to_leave.
        for room_alias in rooms_to_leave:
            # FIXME: remove the user
            logger.info(f'FIXME: remove {user_id} from {room_alias}')

        for room_alias in rooms_to_join:
            try:
                room_id, _ = await room_hanlder.lookup_room_alias(
                    RoomAlias.from_string(room_alias)
                )
                logger.info("room_id for room_alias '%s' is: '%s'",
                            room_alias, room_id)
                if room_id.to_string() in room_ids:
                    logger.info("%s is already a member of %s",
                                user_id, room_alias)
                    continue

                logger.info("Adding %s to room: %s", user_id, room_alias)
                await room_hanlder.update_membership(
                    requester=create_requester(self.admin_user),
                    target=UserID.from_string(user_id),
                    room_id=room_id.to_string(),
                    action=Membership.INVITE,
                    ratelimit=False,
                )
                # force join
                room_hanlder = self.hs.get_room_member_handler()
                await room_hanlder.update_membership(
                    requester=create_requester(user_id),
                    target=UserID.from_string(user_id),
                    room_id=room_id.to_string(),
                    action=Membership.JOIN,
                    ratelimit=False,
                )
            except Exception as e:
                logger.error("Eror adding %s to %s: %r",
                             user_id, room_alias, e)

    def get_local_part(self, epcondata):
        return epcondata["username"]

    async def get_or_create_userid(self, epcondata, password):
        """
        Login/Register the user, setting the appropriate power level.
        """
        localpart = self.get_local_part(epcondata)
        user_id = self.account_handler.get_qualified_user_id(localpart)
        if await self.account_handler.check_user_exists(user_id):
            logger.info("User already exists in Matrix. email: %s",
                        epcondata["email"])
            # exists, authentication complete
            return user_id

        logger.info("User %s is new. Registering in Matrix", localpart)

        # register a new user
        name = f'{epcondata["first_name"]} {epcondata["last_name"]}'
        user_id = await self.register_user(
            localpart=localpart,
            displayname=name,
            emails=[epcondata['email']],
            password=password,
            admin=epcondata['is_staff']
        )
        device_id, access_token = await self.account_handler.register_device(
            user_id
        )
        return user_id

    async def auth_with_epcon(self, email, password):
        try:
            result = await self.http_client.post_json_get_json(
                self.endpoint, {"email": email, "password": password})
        except HttpResponseException as e:
            raise e.to_synapse_error() from e
        if "error" in result:
            logger.info("Error authenticating '%s'", email)
            logger.info("Error message %s", result.get("message"))
            return False
        return result

    def register_user(self, localpart, displayname, emails, password, admin):
        def _do_hash():
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.hashpw(
                pw.encode("utf8") +
                self.hs.config.password_pepper.encode("utf8"),
                bcrypt.gensalt(self.bcrypt_rounds),
            ).decode("ascii")

        return defer.ensureDeferred(
            self.hs.get_registration_handler().register_user(
                localpart=localpart,
                password_hash=_do_hash(),
                default_display_name=displayname,
                bind_emails=emails or [],
                admin=admin
            )
        )


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "Epcon Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )
