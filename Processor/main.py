from parsers import *
import os
import json
import logging
import logging.config

# Constants
app_config_file_name = "config.json"
logging_config_file_name = "logging_config.ini"

def process_configuration_file(config_file_path):
    """
    Load the configuration file and extract the paths.

    Args:
        config_file (str): The path to the configuration file.

    Returns:
        dict: A dictionary containing the file paths.
    """
    with open(config_file_path, 'r') as file:
        config_data = json.load(file)

    base_dir = config_data['base_dir']
    output_dir = config_data['output_dir']

    # Process Analysis
    process_base_dir = os.path.join(base_dir, config_data['process_analysis']['base_directory'])
    process_list_medium_file = os.path.join(process_base_dir, config_data['process_analysis']['process_list_medium_file'])
    process_list_full_file = os.path.join(process_base_dir, config_data['process_analysis']['process_list_full_file'])

    # File Analysis
    file_base_dir = os.path.join(base_dir, config_data['file_analysis']['base_directory'])
    open_files_file = os.path.join(file_base_dir, config_data['file_analysis']['open_files_file'])
    recent_accessed_files_file = os.path.join(file_base_dir, config_data['file_analysis']['recent_accessed_files_file'])
    recent_modified_files_file = os.path.join(file_base_dir, config_data['file_analysis']['recent_modified_files_file'])
    hidden_directories_file = os.path.join(file_base_dir, config_data['file_analysis']['hidden_directories_file'])

    # Network Analysis
    network_base_dir = os.path.join(base_dir, config_data['network_analysis']['base_directory'])
    arp_cache_file = os.path.join(network_base_dir, config_data['network_analysis']['arp_cache_file'])
    ifconfig_file = os.path.join(network_base_dir, config_data['network_analysis']['ifconfig_file'])
    iptables_rules_file = os.path.join(network_base_dir, config_data['network_analysis']['iptables_rules_file'])
    netstat_file = os.path.join(network_base_dir, config_data['network_analysis']['netstat_file'])
    routing_table_file = os.path.join(network_base_dir, config_data['network_analysis']['routing_table_file'])
    ss_file = os.path.join(network_base_dir, config_data['network_analysis']['ss_file'])
    ss_full_file = os.path.join(network_base_dir, config_data['network_analysis']['ss_full_file'])

    # User Analysis
    user_base_dir = os.path.join(base_dir, config_data['user_analysis']['base_directory'])
    last_file = os.path.join(user_base_dir, config_data['user_analysis']['last_file'])
    lastlog = os.path.join(user_base_dir, config_data['user_analysis']['lastlog'])
    w_file = os.path.join(user_base_dir, config_data['user_analysis']['w_file'])
    who_file = os.path.join(user_base_dir, config_data['user_analysis']['who_file'])

    # System Analysis
    system_base_dir = os.path.join(base_dir, config_data['system_analysis']['base_directory'])
    date_file = os.path.join(system_base_dir, config_data['system_analysis']['date_file'])
    df_file = os.path.join(system_base_dir, config_data['system_analysis']['df_file'])
    fdisk_file = os.path.join(system_base_dir, config_data['system_analysis']['fdisk_file'])
    free_file = os.path.join(system_base_dir, config_data['system_analysis']['free_file'])
    hostname_file = os.path.join(system_base_dir, config_data['system_analysis']['hostname_file'])
    hostnamectl_file = os.path.join(system_base_dir, config_data['system_analysis']['hostnamectl_file'])
    installed_packages_file = os.path.join(system_base_dir, config_data['system_analysis']['installed_packages_file'])
    lscpu_file = os.path.join(system_base_dir, config_data['system_analysis']['lscpu_file'])
    lshw_file = os.path.join(system_base_dir, config_data['system_analysis']['lshw_file'])
    lsmod_file = os.path.join(system_base_dir, config_data['system_analysis']['lsmod_file'])
    lspci_file = os.path.join(system_base_dir, config_data['system_analysis']['lspci_file'])
    lsscsi_file = os.path.join(system_base_dir, config_data['system_analysis']['lsscsi_file'])
    lsusb_file = os.path.join(system_base_dir, config_data['system_analysis']['lsusb_file'])
    services_unit_files_file = os.path.join(system_base_dir, config_data['system_analysis']['services_unit_files_file'])
    services_units_file = os.path.join(system_base_dir, config_data['system_analysis']['services_units_file'])
    timedatectl_file = os.path.join(system_base_dir, config_data['system_analysis']['timedatectl_file'])
    timer_units_file = os.path.join(system_base_dir, config_data['system_analysis']['timer_units_file'])
    uname_file = os.path.join(system_base_dir, config_data['system_analysis']['uname_file'])

    # AV Analysis
    av_base_dir = os.path.join(base_dir, config_data['av_analysis']['base_directory'])
    sestatus_file = os.path.join(av_base_dir, config_data['av_analysis']['sestatus_file'])

    # Additional Directories
    etc_directory = os.path.join(base_dir, "etc")
    var_directory = os.path.join(base_dir, "var")
    home_directory = os.path.join(base_dir, "home")
    proc_directory = os.path.join(base_dir, "proc")

    paths_dict = {
        'process_list_medium_file': process_list_medium_file,
        'process_list_full_file': process_list_full_file,
        'open_files_file': open_files_file,
        'recent_accessed_files_file': recent_accessed_files_file,
        'recent_modified_files_file': recent_modified_files_file,
        'hidden_directories_file': hidden_directories_file,
        'arp_cache_file': arp_cache_file,
        'ifconfig_file': ifconfig_file,
        'iptables_rules_file': iptables_rules_file,
        'netstat_file': netstat_file,
        'routing_table_file': routing_table_file,
        'ss_file': ss_file,
        'ss_full_file': ss_full_file,
        'last_file': last_file,
        'lastlog': lastlog,
        'w_file': w_file,
        'who_file': who_file,
        'date_file': date_file,
        'df_file': df_file,
        'fdisk_file': fdisk_file,
        'free_file': free_file,
        'hostname_file': hostname_file,
        'hostnamectl_file': hostnamectl_file,
        'installed_packages_file': installed_packages_file,
        'lscpu_file': lscpu_file,
        'lshw_file': lshw_file,
        'lsmod_file': lsmod_file,
        'lspci_file': lspci_file,
        'lsscsi_file': lsscsi_file,
        'lsusb_file': lsusb_file,
        'services_unit_files_file': services_unit_files_file,
        'services_units_file': services_units_file,
        'timedatectl_file': timedatectl_file,
        'timer_units_file': timer_units_file,
        'uname_file': uname_file,
        'sestatus_file': sestatus_file,
        'etc_directory': etc_directory,
        'var_directory': var_directory,
        'home_directory': home_directory,
        'proc_directory': proc_directory,
        'base_dir': base_dir,
        'output_dir': output_dir
    }

    return paths_dict

def write_json_string_to_file(json_string, file_path):
    """
    Write a JSON string to a file.
    
    Args:
        json_string (str): JSON string to be written.
        file_path (str): Path to the file where JSON will be written.
    
    Returns:
        None
    """
    try:
        with open(file_path, 'w') as file:
            file.write(json_string)
        print(f"JSON string successfully written to file: {file_path}")
        logging.info("JSON string successfully written to file: %s", file_path)
    except Exception as e:
        logging.error("Error writing output to file: %s", str(e))



def main():
    # Get the absolute path to the module
    module_path = os.path.abspath(os.path.dirname(__file__))
    logging_config_file = os.path.join(module_path, logging_config_file_name)

    # Check if the configuration file exists
    if not os.path.isfile(logging_config_file):
        raise FileNotFoundError(f"Logging configuration file not found: {logging_config_file}")

    # Configure logging
    # Load the logging configuration from the file
    logging.config.fileConfig(logging_config_file)

    # Get the logger instance for the main module
    logger = logging.getLogger(__name__)

    logger.info("Main module started.")
    
    # Initialize paths dictionary from the config file
    app_config_file_path = os.path.join(module_path, app_config_file_name)
    paths_dict = process_configuration_file(app_config_file_path)
    
    # Execute procfs parser
    #procfs_json = procfs_parser.parse(paths_dict['proc_directory'])
    #procfs_json_path = os.path.join(paths_dict['output_dir'], 'procfs_json.json')
    #write_json_string_to_file(procfs_json, procfs_json_path)

    # Execute ps command parser
    #ps_full_json = ps_full_command_parser.parse(paths_dict['process_list_full_file'])
    #ps_full_json_path = os.path.join(paths_dict['output_dir'], 'ps_full_json.json')
    #write_json_string_to_file(ps_full_json, ps_full_json_path)

    # Execute the netstat command parser
    #netstat_json = netstat_command_parser.parse(paths_dict['netstat_file'])
    #netstat_json_path = os.path.join(paths_dict['output_dir'], 'netstat_json.json')
    #write_json_string_to_file(netstat_json, netstat_json_path)

    # Execute the lsmod command parser
    #lsmod_json = lsmod_command_parser.parse(paths_dict['lsmod_file'])
    #lsmod_json_path = os.path.join(paths_dict['output_dir'], 'lsmod_json.json')
    #write_json_string_to_file(lsmod_json, lsmod_json_path)

    # Execute the passwd file parser
    passwd_file_path = os.path.join(paths_dict['etc_directory'], 'passwd')
    passwd_json = passwd_file_parser.parse(passwd_file_path)
    passwd_json_path = os.path.join(paths_dict['output_dir'], 'passwd_json.json')
    write_json_string_to_file(passwd_json, passwd_json_path)

    # Execute the group file parser
    group_file_path = os.path.join(paths_dict['etc_directory'], 'group')
    group_json = group_file_parser.parse(group_file_path)
    group_json_path = os.path.join(paths_dict['output_dir'], 'group_json.json')
    write_json_string_to_file(group_json, group_json_path)

    # Execute the hosts file parser
    hosts_file_path = os.path.join(paths_dict['etc_directory'], 'hosts')
    hosts_json = hosts_file_parser.parse(hosts_file_path)
    hosts_json_path = os.path.join(paths_dict['output_dir'], 'hosts_json.json')
    write_json_string_to_file(hosts_json, hosts_json_path)

    # Execute sestatus command parser
    #sestatus_json = sestatus_command_parser.parse(paths_dict['sestatus_file'])
    #sestatus_json_path = os.path.join(paths_dict['output_dir'], 'sestatus_json.json')
    #write_json_string_to_file(sestatus_json, sestatus_json_path)



    """
    print("Process Analysis:")
    print(paths_dict['process_list_medium_file'])
    print(paths_dict['process_list_full_file'])

    print("\nFile Analysis:")
    print(paths_dict['open_files_file'])
    print(paths_dict['recent_accessed_files_file'])
    print(paths_dict['recent_modified_files_file'])
    print(paths_dict['hidden_directories_file'])

    print("\nNetwork Analysis:")
    print(paths_dict['arp_cache_file'])
    print(paths_dict['ifconfig_file'])
    print(paths_dict['iptables_rules_file'])
    print(paths_dict['netstat_file'])
    print(paths_dict['routing_table_file'])
    print(paths_dict['ss_file'])
    print(paths_dict['ss_full_file'])

    print("\nUser Analysis:")
    print(paths_dict['last_file'])
    print(paths_dict['lastlog'])
    print(paths_dict['w_file'])
    print(paths_dict['who_file'])

    print("\nSystem Analysis:")
    print(paths_dict['lsusb_file'])
    print(paths_dict['lsmod_file'])
    print(paths_dict['services_units_file'])

    print("\nAV Analysis:")
    print(paths_dict['sestatus_file'])
    """
    logger.info("Main module completed.")

if __name__ == "__main__":
    main()