import getpass
import json
import re

import ldap

from loguru import logger

import yaml


with open("config.yaml", "r") as stream:
    try:
        yaml_data = yaml.safe_load(stream)
        LDAP_URI = yaml_data["ldap"]["LDAP_URI"]
        LDAP_BASE_DN = yaml_data["ldap"]["LDAP_BASE_DN"]
        LDAP_WHO_TEMPLATE = yaml_data["ldap"]["LDAP_WHO_TEMPLATE"]
        LDAP_WHO_EXT_TEMPLATE_0 = yaml_data["ldap"]["LDAP_WHO_EXT_TEMPLATE_0"]
        LDAP_WHO_EXT_TEMPLATE_1 = yaml_data["ldap"]["LDAP_WHO_EXT_TEMPLATE_1"]
        LDAP_WHO_EXT_TEMPLATE_2 = yaml_data["ldap"]["LDAP_WHO_EXT_TEMPLATE_2"]
        LDAP_WHO_EXT_TEMPLATE_3 = yaml_data["ldap"]["LDAP_WHO_EXT_TEMPLATE_3"]
    except yaml.YAMLError as exc:
        print(exc)


TEMPLATES = [
    LDAP_WHO_TEMPLATE,
    LDAP_WHO_EXT_TEMPLATE_0,
    LDAP_WHO_EXT_TEMPLATE_1,
    LDAP_WHO_EXT_TEMPLATE_2,
    LDAP_WHO_EXT_TEMPLATE_3,
]


class UserAuthenticationException(Exception):
    pass


class User(object):
    """Authenticate user with Active Directory credentials"""

    def __init__(self, user, password=None):
        self.staff = False
        self.username = user
        self.password = password
        self.ldap_connect()
        if password:
            self.authenticate(password)

    def authenticate(self, password=None):
        if password is None:
            password = getpass.getpass(f"Password for {self.username} ?")

        ldc = self._conn
        user = self.username

        auth_ok = False
        for tpl in TEMPLATES:
            who = tpl.format(user)
            logger.info(f"Attempting to authenticate against: {who}...")
            try:
                ldc.simple_bind_s(who, password)
                auth_ok = True
                break
            except ldap.INVALID_CREDENTIALS as e:
                logger.info(f"...failed. {e}")
            except ldap.LDAPError as e:
                logger.exception(f"failed ext account not tried. {e}")

        if not auth_ok:
            raise ldap.INVALID_CREDENTIALS

        res = ldc.search(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, f"(cn={user})")
        restype, resdata = ldc.result(res, 0)

        info = resdata[0][1]

        for k, v in info.items():
            nv = [s.decode("utf-8", "ignore") if isinstance(s, bytes) else s for s in v]
            info[k] = nv

        for group in info["memberOf"]:
            if "unx-MXgroup" in group:
                self.staff = True
                break

        # get the ldap info into easy variables
        self.fields = [
            "cn",
            "displayName",
            "givenName",
            "initials",
            "mail",
            "physicalDeliveryOfficeName",
            "sn",
            "telephoneNumber",
        ]

        self.__dict__.update(info)

        self.pgroups = []
        for item in self.memberOf:
            if re.match("^CN=(p[0-9]{5}).*$", item):
                pgroup = re.match("^CN=(p[0-9]{5}).*$", item).group(1)
                self.pgroups.append(pgroup)

    def encodeJson(self):
        return json.dumps(self.fields)

    def ldap_connect(self):
        self._conn = ldap.initialize(LDAP_URI)
