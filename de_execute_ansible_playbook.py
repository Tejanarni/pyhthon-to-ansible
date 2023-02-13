"""
Entrypoint python script to execute ansible playbook command.
"""
import ansible_runner
import argparse
import json
import os
import sys


sys.path.append(os.path.dirname(__file__))
import helpers

os.chdir(os.path.dirname(os.path.realpath(__file__)))


###Python to Ansible

def DHCPconfiguration():
  extravars = {
    'dcname': args.dcname
  }

  if args.env == 'prod':
    extravars['ignore_docker_validation_arg'] = 'False'
  else:
    extravars['ignore_docker_validation_arg'] = 'True'

  execute_playbook("DHCPconfiguration.yml", extravars)



def kernel_update():
  extravars = {
    'KernelTargetVersion': args.KernelTargetVersion
  }

  if args.env == 'prod':
    extravars['ignore_docker_validation_arg'] = 'False'
  else:
    extravars['ignore_docker_validation_arg'] = 'True'

  execute_playbook("kernel_update.yaml", extravars)

def deploy_rescue_artifacts():

  extravars = {
    'role': args.role,
    'env': args.env,
    'build_version': args.build_version,
    'ignore_health_check' : False
  }

  execute_playbook("deploy.yaml", extravars)

def deploy_rescue_rr_data():
  execute_playbook("recursive_data_deployment.yaml")

def add_host_keys_for_server(servers):
  for server in servers:
    helpers.exec_command("ssh-keygen -t ssh-rsa -R " + server +" 2>/dev/null")
    helpers.exec_command("ssh-keyscan -t ssh-rsa  " + server + " >> ~/.ssh/known_hosts 2>/dev/null")

'''
  Validate if ansible playbook deployment is successfull or not.
  Ansible return code will be non zero if any one of the host is not
  successfull. It does not take into account max_failure_allowed_percentage.
  We will determine failure as below
    * if playbook is not executed in all the hosts or
    * if number of failed hosts exceeds max allowed failed percentage
'''
def is_ansible_playbook_execution_failed(servers, ansible_output):
  # total number of servers processed by ansible playbook
  servers_processed = set()
  for ansible_state in ansible_output.stats.keys():
    servers_in_given_ansible_state = ansible_output.stats[ansible_state]
    for server in servers_in_given_ansible_state.keys():
      servers_processed.add(server)
      helpers.emit_metric(
        "AnsibleExecutionStatus", 1, state=ansible_state, RoleInstance=server,
        Env=args.env, Role=args.role, action=args.action
      )

  failed_servers_count = len(ansible_output.stats['failures'].keys())
  total_servers = len(servers)

  print ("Total servers: {}, servers processed: {}, failed servers count: {}, percentage of failed server: {}".format(total_servers, len(servers_processed) , failed_servers_count, (failed_servers_count/total_servers)))
  return total_servers != len(servers_processed) or (failed_servers_count/ total_servers >= float(args.max_failure_allowed_percentage))

def get_ansible_output(ansible_output,emit_metrics=False):
  servers_processed = set()
  for ansible_state in ansible_output.stats.keys():
    servers_in_given_ansible_state = ansible_output.stats[ansible_state]
    for server in servers_in_given_ansible_state.keys():
      servers_processed.add(server)
      if emit_metrics:
        helpers.emit_metric(
          "AnsibleExecutionStatus", 1, state=ansible_state, RoleInstance=server,
          Env=args.env, Role=args.role, action=args.action
        )

  failed_servers_count = len(ansible_output.stats['failures'].keys())
  return servers_processed, failed_servers_count

def execute_ansible_run(playbook_name, extravars={}):
  extravars['serial_deploy_percentage'] = args.rolling_update_percentage
  extravars['max_failed_percentage'] = args.max_failure_allowed_percentage
  playbook_tags = args.playbook_tags if args.playbook_tags else None

  ansible_output = ansible_runner.run(
          private_data_dir=os.path.dirname(os.getcwd()),
          project_dir=os.path.dirname(os.getcwd()),
          playbook=playbook_name,
          inventory=args.inventory,
          extravars=extravars,
          limit=args.inv_limit,
          tags=playbook_tags
      )
  return ansible_output

def execute_playbook(playbook_name, extravars={}):

  # execute ping command on all machine to get list of servers to validate results later
  ping_output = execute_ansible_run("ping.yaml")
  print("ping playbook status {}: {}".format(ping_output.status, ping_output.rc))
  print(ping_output.stats)

  servers = get_ansible_output(ping_output)[0]
  # add host key for servers
  add_host_keys_for_server(servers)

  # execute ansible playbook
  ansible_output = execute_ansible_run(playbook_name,extravars)
  # Ansible error code will be non zero even if one hosts failed.
  if is_ansible_playbook_execution_failed(servers, ansible_output):
    print ("Ansible playbook execution failed")
    helpers.emit_metric(
      "AnsibleExecutionFailure", 1, Env=args.env, Role=args.role, action=args.action
    )
    exit(1)

  print("Ansible playbook status {}: {}".format(ansible_output.status, ansible_output.rc))
  print(ansible_output.stats)

# def deploy_tm_map():

#   extravars = {
#     'remote_tm_map_basepath': args.tm_map_basepath,
#     'local_map_files_location': args.local_map_location
#   }

#   for map_config_file in args.map_config_files:
#     map_config_path = os.path.join(args.local_map_location, map_config_file)
#     with open(map_config_path) as file_read:
#       data = json.load(file_read)

#     for section in ('RegionPreference', 'SubnetMapping'):
#       if section in data and 'Partitions' in data[section]:
#         for partition in data[section]['Partitions']:
#           if 'Name' in partition and not partition['Name'].startswith(args.map_config_container_basepath):
#             partition['Name'] = os.path.join(args.map_config_container_basepath, partition['Name'])

#     with open(map_config_path, "w") as file_write:
#       json.dump(data, file_write)

#   execute_playbook('deploy_tm_map.yaml', extravars)

# def rollback_tm_map():
#   extravars = {
#     'remote_tm_map_basepath': args.tm_map_basepath
#   }

#   execute_playbook('rollback_tm_map.yaml', extravars)

def upload_to_puppet():
  extravars = {
    'role': args.role,
    'env': args.env,
    'build_version': args.build_version,
    'ignore_health_check' : False
  }
  execute_playbook('upload_puppet_master.yaml', extravars)

parser = argparse.ArgumentParser()
parser.add_argument('--env', help='Environment', type=str)
parser.add_argument('--role', help='Service role', type=str,  choices=['recursive','auth', 'rescuepp', 'tmmap', 'rescuerrdata'])
parser.add_argument('--inv_limit', help='Inventory limit param for ansible playbook to be run', type=str)
parser.add_argument('--inventory', help='Inventory param for ansible playbook to be run', type=str)
parser.add_argument('--action', help='action to be performed', type=str, choices=['deploy', 'kernelUpdate', 'rollback', 'configure_puppet_agent', 'ansible_setup', 'bootstrap_syncagent_snapshot', 'puppet_upload'])
parser.add_argument('--playbook_tags', help='tags to be run for the playbook', type=str, choices=['puppet_upload'])
parser.add_argument('--build_version', help='Build version to be deployed', type=str)
parser.add_argument('--max_failure_allowed_percentage', help='Maximum failure allowed percentage for ansible action', default='50', type=str)
parser.add_argument('--rolling_update_percentage', help='Number of hosts to execute ansible playbook simultaneously', default='50%', type=str)

parser.add_argument('--KernelTargetVersion', help='Kernel Target Version for patching', default='noVersion', type=str)

parser.add_argument('--tm_map_basepath', help='The basepath where the TM map files are deployed on rescuepp dns servers', default='/var/data/rescue/knot/cache', type=str)
parser.add_argument('--local_map_location', help='The path where the TM map files are uploaded locally (ansible master)', type=str)
parser.add_argument('--map_config_files', help='The json files that store the map config. Use separate arg for each file', action='append')
parser.add_argument('--map_config_container_basepath', help='The base path to the config files from the perspective of the knot container', default='/var/knot/cache/Current', type=str)

args = parser.parse_args()

if args.action == "puppet_upload":
  if not args.env or not args.inv_limit:
    raise ValueError('Required argument (env, inv_limit) not provided for action puppet_upload')
  upload_to_puppet()
elif args.action == "deploy":
  if args.role == "rescuerrdata":
    if not args.inv_limit:
      raise ValueError('Required argument (inv_limit) not provided for action deploy')
    deploy_rescue_rr_data()
  # elif args.role == "tmmap":
  #   if not args.env or not args.tm_map_basepath or not args.local_map_location or not args.map_config_files or not args.map_config_container_basepath:
  #     raise ValueError("Required argument (env, tm_map_basepath, local_map_location, map_config_files, map_config_container_basepath) not provided for action deploy for tm_map")
  #   deploy_tm_map()
  else:
    if not args.env or not args.role or not args.build_version:
      raise ValueError('Required argument (env, role, build_version) not provided for action deploy')
    deploy_rescue_artifacts()
elif args.action == "kernelUpdate":
  if not args.env or not args.role:
    raise ValueError('Required argument (env, role, build_version) not provided for action deploy')
  kernel_update()
elif args.action == "rollback":
  if args.role != "tmmap":
    if not args.env or not args.role or not args.build_version:
      raise ValueError('Required argument (env, role, build_version) not provided for action rollback')
    deploy_rescue_artifacts()
  else:
    if not args.env or not args.tm_map_basepath:
      raise ValueError("Required argument (env, tm_map_basepath) not provided for action rollback for tm_map")
    #rollback_tm_map()
