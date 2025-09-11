#!/usr/bin/env python

import requests
from requests.auth import HTTPBasicAuth
import argparse
import os
import sys
import warnings
import argparse
import logging
 
try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import SafeConfigParser
 
warnings.filterwarnings("ignore")
 
DEFAULT_CREDENTIALS_FILE = os.path.expanduser('~/.mitsogo/credentials')
logger = logging.getLogger(__name__)
FORMAT = "%(asctime)s {} {} - %(levelname)s - %(message)s".format(os.uname()[1],os.environ.get('technician','SYSTEM'))
logging.basicConfig(format=FORMAT, level=os.environ.get('LOGLEVEL','INFO'))
configParser = SafeConfigParser()
 
def getconfig(profile,variable,environment,default=""):
    try:
        configParser.read(os.environ.get('SHARED_CREDENTIALS_FILE', DEFAULT_CREDENTIALS_FILE))
        value = configParser.get(profile, variable)
    except:
        value = os.environ.get(environment,default)
    return value
 
JENKINS_URL = "https://beta-jenkins.mitsogo.com"
USERNAME = "1aaa800e-49d0-4596-8e99-1aa5230fe693"
API_TOKEN = "11e6e11599fe7cb50550b8f70f949acf4a"
role_types = {"globalRoles":"Global", "projectRoles":"Project", "slaveRoles":"Slave"}
 
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded"
}
 


def assign_role(role_type, role_name, sid):
    """
    Assigns a user or group to a Jenkins role.
    """
 
    script_console_url = "{}/scriptText".format(JENKINS_URL)
 
    groovy_script = """
    import com.michelin.cio.hudson.plugins.rolestrategy.AuthorizationType
    import com.michelin.cio.hudson.plugins.rolestrategy.PermissionEntry
    import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy
    import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleType
    import jenkins.model.Jenkins
 
    def jenkins = Jenkins.get()
    def rbas = jenkins.getAuthorizationStrategy()
 
    if (!(rbas instanceof RoleBasedAuthorizationStrategy)) {
        println "Current strategy is not RoleBasedAuthorizationStrategy."
        return
    }
 
    def roleMap = rbas.getRoleMap(RoleType.%s)
 
    def role = roleMap.getRole("%s")
    if (!role) {
        print "Role '%s' does not exist."
        return
    }
 
   
    roleMap.assignRole(role, new PermissionEntry(AuthorizationType.GROUP, '%s'))
 
    jenkins.save()
    print "Assigned user '%s' to %s role '%s'."
    """ % (role_type, role_name, role_name, sid, sid, role_type, role_name)
 
    payload = {
        "script": groovy_script
    }
 
    response = requests.post(
        script_console_url,
        auth=(USERNAME, API_TOKEN),
        headers=HEADERS,
        data=payload
    )
 
    if response.status_code == 200:
        text = response.text.strip()
        if "Assigned user" in text:
            logger.info(text)
            return True
        else:
            logger.info("Role '{}' not found in {}Roles, skipping....".format(role_name,role_type))
            return False
    else:
        logger.error("Could not post the request. Response code : {}".format(response.status_code))
        return False
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Assign Jenkins roles to a user.")
    parser.add_argument("--username", help="Username to assign roles to.")
    parser.add_argument("--roles", help="Comma-separated list of roles to assign.")
    args = parser.parse_args()

    sid = args.username
    role_names = args.roles

    
    for role_name in [r.strip() for r in role_names.split(",") if r.strip()]:
        assigned = False
        for role_type_key in ["globalRoles", "projectRoles"]:
            role_type_for_groovy = role_types.get(role_type_key)
            if not role_type_for_groovy:
                logger.error("Invalid Roletype")
                continue
            if assign_role(role_type_for_groovy, role_name, sid):
                assigned = True
        if not assigned:
            logger.error("Role '{}' not found in any role type. ".format(role_name))
            sys.exit(1)
    sys.exit(0)
    

