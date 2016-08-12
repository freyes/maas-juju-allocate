#!/usr/bin/python3

import argparse
import datetime
import ipaddress
import json
import logging
import os
import subprocess
import sys
import tempfile

from pprint import pprint

FORMAT = '%(asctime)-15s %(levelname)-8s %(message)s'
logging.basicConfig(level=logging.DEBUG, format=FORMAT, stream=sys.stderr)
LOG = logging.getLogger()

import yaml
try:
    from apiclient import maas_client
    from apiclient import creds as maas_creds
    from maascli import auth as maas_auth
except ImportError:
    LOG.error('maas api client not found, run '
              '"apt-get install python3-maas-client"\n')
    sys.exit(1)

API_KEY = os.environ.get('MAAS_API_KEY')
API_URL = os.environ.get('MAAS_API_URL')


def setup_options(argv=None):
    parser = argparse.ArgumentParser(description=('Create devices and allocate'
                                                  ' addresses for lxd '
                                                  'containers'))
    parser.add_argument('--mac-addresses', dest='mac_addresses_fpath',
                        required=True, metavar='FILE')
    parser.add_argument('--force-linking', dest='force_linking',
                        action='store_true',
                        help=("links interface to subnet no matter if it's "
                              "already linked"))
    parser.add_argument('--write-interfaces', dest="write_interfaces",
                        action="store_true")

    return parser.parse_args(argv)


def juju_status():
    output = subprocess.check_output(['juju-2.0', 'status', '--format', 'yaml'])

    return yaml.safe_load(output)


def get_maas_client(api_url, api_key):

    creds = maas_auth.obtain_credentials(api_key)
    if not maas_auth.check_valid_apikey(api_url, creds):
        LOG.error('Invalid credentials %s : %s\n', api_url, creds)
        sys.exit(2)

    oauth = maas_client.MAASOAuth(*creds)
    client = maas_client.MAASClient(oauth, maas_client.MAASDispatcher(),
                                    api_url)
    return client


def get_devices(client, params={}):
    return json.loads(client.get('/devices/', **params).read().decode('utf-8'))


def is_registered_device(client, mac_address):
    d = get_devices(client, {'mac_address': mac_address})
    LOG.debug('Is %s registered? -> %s', mac_address, len(d) > 0)
    return len(d) > 0

def create_device(client, parent_id, hostname, mac_address):
    LOG.debug('creating device-> parent %s, hostname: %s, mac address: %s',
              parent_id, hostname, mac_address)
    response = client.post('/devices/', op=None, as_json=True,
                           hostname=hostname,
                           mac_addresses=[mac_address],
                           parent=parent_id)
    device = json.loads(response.read().decode('utf-8'))
    return device


def update_device(client, system_id, interface_id, **kwargs):
    response = client.put('/nodes/{}/interfaces/{}/'
                              .format(system_id, interface_id),
                          **kwargs)
    device = json.loads(response.read().decode('utf-8'))
    return device


def link_subnet_to_interface(client, device_id, interface_id, subnet_id):
    LOG.debug('linking device %s, interface %s to subnet %s',
              device_id, interface_id, subnet_id)

    response = client.post('/nodes/{}/interfaces/{}/'
                           .format(device_id, interface_id),
                           op='link_subnet',
                           as_json=True,
                           mode='STATIC',
                           subnet=subnet_id,
                           default_gateway=False)
    device = json.loads(response.read().decode('utf-8'))
    return device


def get_subnet(client, subnet):
    r = client.get('/subnets/')
    for item in json.loads(r.read().decode('utf-8')):
        if item['name'] == subnet:
            return item

    raise Exception('subnet %s not found' % subnet)


def find_ips(interface):
    ips = []
    for link in interface['links']:
        if 'ip_address' in link and link['ip_address']:
            ips.append(link['ip_address'])

    return set(ips)


def get_interface(client, system_id, interface_id):
    response = client.get('/nodes/{}/interfaces/{}/'.format(system_id,
                                                            interface_id))
    interface = json.loads(response.read().decode('utf-8'))
    return interface


def get_link(client, system_id, interface_id, ip_address):
    interface = get_interface(client, system_id, interface_id)
    for link in interface['links']:
        if link['ip_address'] == ip_address:
            return link

    LOG.warning("system %s with interface %s doesn't have a link with IP %s",
                system_id, interface_id, ip_address)
    return None


def print_interface_setup(device, interface, link, eth):
    print('###### details #####')
    print('# system id (device): {}'.format(device['system_id']))
    print('# parent device id: {}'.format(device['parent']))
    print('# interface id: {}'.format(interface['id']))
    print('# mac address: {}'.format(interface['mac_address']))
    print('# Link:')
    print('# - IP address: {}'.format(link['ip_address']))
    print('# - subnet: {}'.format(link['subnet']['name']))
    print(get_interface_setup(device, interface, link, eth))


def get_interface_setup(device, interface, link, eth):
    content = ""
    ip = ipaddress.ip_address(link['ip_address'])
    if ip.version == 6:
        family = 'inet6'
    else:
        family = 'inet'

    network = ipaddress.ip_network(link['subnet']['cidr'])

    content += 'iface {} {} static\n'.format(eth, family)
    content += '  address {}/{}\n'.format(link['ip_address'],
                                          network.prefixlen)

    if link['subnet']['gateway_ip']:
        content += '  gateway {}\n'.format(link['subnet']['gateway_ip'])

    return content


def is_iface_linked(interface, subnet_id, dev):
    linked = False
    allocated_ips = []
    for link in interface['links']:
        if 'subnet' in link and link['subnet']['id'] == subnet_id:
            linked = True
            LOG.debug("link found! -> id: %s, system: %s, interface: %s, "
                      " ip address %s", link['id'], dev['system_id'],
                      interface['id'], link['ip_address'])
            allocated_ips.append(link['ip_address'])

    return (linked, allocated_ips)


def connect_interface_to_subnet(client, dev, interface, subnet):
    LOG.debug('Connecting device %s, interface %s to vlan %s',
              dev['system_id'], interface['id'], subnet['vlan']['id'])
    new_dev = update_device(client, dev['system_id'],
                            interface['id'],
                            vlan=str(subnet['vlan']['id']))
    return {**dev, **new_dev}


def find_interface(device, mac_address):

    for interface in device['interface_set']:
        if interface['mac_address'] == mac_address:
            return interface


def juju_get_machine(j_status, instance_id):
    for machine_id, machine in j_status['machines'].items():
        if machine['instance-id'] == instance_id:
            return (machine_id, machine)


def juju_get_container(machine, container_id):
    for cid, container in machine.get('containers', {}).items():
        if container['instance-id'] == container_id:
            return (cid, container)


def get_container_config(machine_id, container_id):
    out = subprocess.check_output(['juju-2.0', 'run', '--machine', machine_id,
                                   'sudo lxc config show %s' % container_id])
    config = yaml.safe_load(out)
    return config


def find_eth(machine_id, container_id, mac_address):
    config = get_container_config(machine_id, container_id)
    for eth, item in config['devices'].items():
        if item.get('hwaddr') == mac_address:
            return eth

def read_etc_network_interfaces(id_):
    out = subprocess.check_output(['juju-2.0', 'run', '--machine', id_,
                                   'cat /etc/network/interfaces'],
                                  universal_newlines=True)
    return out


def juju_scp(src, dst):
    subprocess.check_call(['juju-2.0', 'scp', src, dst])


def write_interface_setup(device, interface, link, mid, cid, cins_id, eth,
                          write_changes=False):
    current = read_etc_network_interfaces(cins_id)
    chunk = get_interface_setup(device, interface, link, eth)
    new_content = ""
    if chunk.strip() not in current:
        new_content = current + '\n\n' + chunk

    if new_content:
        sufix = datetime.datetime.now().strftime('%Y-%m-%dT%H%M%S')
        subprocess.check_output(['juju-2.0', 'run', '--machine', cins_id,
                                 ('sudo cp /etc/network/interfaces '
                                  '/etc/network/interfaces.%s') % sufix])
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(str.encode(new_content))
            f.flush()
            juju_scp(f.name, '%s:/tmp/interfaces' % cins_id)

        if write_changes:
            subprocess.check_call(['juju-2.0', 'run', '--machine', cins_id,
                                   ('sudo cp /tmp/interfaces '
                                    '/etc/network/interfaces')])


def lxc_noop(machine_id):
    # the first time a 'lxc' command is used a client certificate
    # is generated and the command requested is ignored
    # with this we make sure the certificate is generated
    # so then we can just rely on that the lxc commands will succeed
    subprocess.check_output(['juju-2.0', 'run', '--machine', machine_id,
                             'sudo lxc list'])


def main(argv=None):

    opts = setup_options(argv)
    client = get_maas_client(API_URL, API_KEY)
    if not os.path.isfile(opts.mac_addresses_fpath):
        LOG.error('mac addresses file not found: %s', opts.mac_addresses_fpath)

    with open(opts.mac_addresses_fpath) as f:
        macs = yaml.safe_load(f)

    j_status = juju_status()

    for parent_id in macs['machines']:
        (mid, j_machine) = juju_get_machine(j_status, parent_id)
        if not j_machine:
            LOG.warning('machine %s not found, skipping it', parent_id)
            continue

        lxc_noop(mid)

        for hostname in macs['machines'][parent_id]:

            cid = hostname.split('.')[0]
            (cins_id, j_container) = juju_get_container(j_machine, cid)
            if not j_container:
                LOG.warning('container %s in machine %s not found, skipping it',
                            cid, parent_id)
                continue

            for net in macs['machines'][parent_id][hostname]['interfaces']:
                registered = is_registered_device(client, net['mac_address'])

                if not registered:
                    dev = create_device(client, parent_id, hostname,
                                        net['mac_address'])
                else:
                    devs = get_devices(client,
                                       {'mac_address': net['mac_address']})
                    dev = devs[0]

                interface = find_interface(dev, net['mac_address'])
                assert interface != None
                for subnet_name in net['subnets']:
                    subnet = get_subnet(client, subnet_name)
                    (linked, allocated_ips) = is_iface_linked(interface,
                                                              subnet['id'],
                                                              dev)

                    if linked:
                        LOG.info(("Skipping already linked device %s, "
                                  "interface %s to subnet %s"),
                                 dev['system_id'], interface['id'],
                                 subnet['id'])
                    else:
                        connect_interface_to_subnet(client, dev, interface,
                                                    subnet)
                        # get a fresh interface object after it was
                        # connected to the subnet
                        iface = get_interface(client, dev['system_id'],
                                              interface['id'])

                        # get ips the interface has to then compare
                        # and find out which IP was assigned
                        ips_before = find_ips(iface)
                        # plug the interface so we get an IP
                        r = link_subnet_to_interface(client,
                                                     dev['system_id'],
                                                     iface['id'],
                                                     subnet['id'])

                        ips_after = find_ips(r)
                        allocated_ips = ips_after - ips_before

                    if len(allocated_ips) == 0:
                        LOG.error("Couldn't find allocated ip")
                        continue

                    if len(allocated_ips) > 1:
                        LOG.warning("Found ips %s, using first",
                                    allocated_ips)
                    allocated_ip = list(allocated_ips)[0]
                    link = get_link(client,
                                    dev['system_id'],
                                    interface['id'],
                                    allocated_ip)
                    eth = find_eth(mid, cid, net['mac_address'])
                    print_interface_setup(dev, interface, link, eth)

                    write_interface_setup(dev, interface, link,
                                          mid, cid, cins_id, eth,
                                          opts.write_interfaces)


if __name__ == "__main__":
    main()
