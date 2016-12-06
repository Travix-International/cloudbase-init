# Copyright 2014 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import json
import posixpath

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import encoding
from cloudbaseinit.utils import x509constants

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class BaseOpenStackService(base.BaseMetadataService):

    def get_content(self, name):
        path = posixpath.normpath(
            posixpath.join('openstack', 'content', name))
        return self._get_cache_data(path)

    def get_user_data(self):
        path = posixpath.normpath(
            posixpath.join('openstack', 'latest', 'user_data'))
        return self._get_cache_data(path)

#    def _get_meta_data(self, version='latest'):
#        path = posixpath.normpath(
#            posixpath.join('openstack', version, 'meta_data.json'))
#        data = self._get_cache_data(path, decode=True)
#        if data:
#            return json.loads(data)

    def _get_generic_data(self, name, version='latest'):
        path = posixpath.normpath(
            posixpath.join('openstack', version, name))
        data = self._get_cache_data(path, decode=True)
        if data:
            return json.loads(data)

    def _get_meta_data(self):
        return self._get_generic_data('meta_data.json')

    def _get_network_data(self):
        return self._get_generic_data('network_data.json')

    def _get_meta_data(self, version='latest'):
        path = posixpath.normpath(
            posixpath.join('openstack', version, 'meta_data.json'))
        data = self._get_cache_data(path, decode=True)
        if data:
            return json.loads(data)

    def get_instance_id(self):
        return self._get_meta_data().get('uuid')

    def get_host_name(self):
        return self._get_meta_data().get('hostname')

    def get_public_keys(self):
        """Get a list of all unique public keys found among the metadata."""
        public_keys = []
        meta_data = self._get_meta_data()
        public_keys_dict = meta_data.get("public_keys")
        if public_keys_dict:
            public_keys = list(public_keys_dict.values())
        keys = meta_data.get("keys")
        if keys:
            for key_dict in keys:
                if key_dict["type"] == "ssh":
                    public_keys.append(key_dict["data"])
        return list(set((key.strip() for key in public_keys)))

    def get_network_details(self):
        """Example of network_data.json:
	{
	    "links": [
	        {
	            "ethernet_mac_address": "fa:16:3e:98:28:83",
	            "id": "tap6c24009c-9c",
	            "mtu": 1500,
	            "type": "bridge",
	            "vif_id": "6c24009c-9c51-4a01-bccb-0488fc3d539d"
	        }
	    ],
	    "networks": [
	        {
	            "id": "network0",
	            "ip_address": "172.16.16.6",
	            "link": "tap6c24009c-9c",
	            "netmask": "255.255.255.128",
	            "network_id": "a7ffd6e4-3600-4d21-a785-4c1f89101b6f",
	            "routes": [
	                {
	                    "gateway": "172.16.16.126",
	                    "netmask": "0.0.0.0",
	                    "network": "0.0.0.0"
	                }
	            ],
	            "type": "ipv4"
	        }
	    ],
	    "services": [
	        {
	            "address": "8.8.8.8",
	            "type": "dns"
	        }
	    ]
	}
	"""
        # Try retrieving and parsing the network data JSON.
        try:
            network_data = self._get_network_data()
            LOG.warn("!!!! Network data: %s" % network_data)
        except base.NotExistingMetadataException:
            LOG.debug("Network data in JSON format not found; "
                      "fallback to network_config.")
        else:
            if network_data:
                # Collect DNS name servers.
                dns_servers = []
                for service in network_data["services"]:
                    if service["type"] == "dns":
                        dns_servers.append(service["address"])
                # Extract basic details by links over networks.
                links = {}
                for link in network_data["links"]:
                    links[link["id"]] = link
                networks = {}
                for network in network_data["networks"]:
                    networks[network["link"]] = network

                nics = []
                for link_id, link in links.items():
                    LOG.warn("!!!! link[type]: %s" % link["type"])
                    if link["type"] in ("vif", "phy", "ovs", "bridge"):
                        network = networks[link_id]
                        suffix = "6" if network["type"] == "ipv6" else ""
                        nic = dict.fromkeys(base.FIELDS)
                        nic["dnsnameservers"] = dns_servers
                        nic["name"] = network["id"]
                        nic["mac"] = link["ethernet_mac_address"].upper()
                        address = network["ip_address"]
                        if suffix:
                            pass
                        else:
                            nic["address"] = address
                            nic["netmask"] = network["netmask"]
                        for route in network["routes"]:
                            if route["network"] == "0.0.0.0":
                                #set default gateway
                                nic["gateway"] = route["gateway"]
                        nics.append(base.NetworkDetails(**nic))
                LOG.warn("!!!! Nics: %s" % nics)
                return nics

        # Parse the Debian-like network configuration content.
        network_config = self._get_meta_data().get('network_config')
        LOG.debug("Openstack network config raw: %s" % network_config)
        if not network_config:
            return None
        key = "content_path"
        if key not in network_config:
            return None

        content_name = network_config[key].rsplit("/", 1)[-1]
        content = self.get_content(content_name)
        content = encoding.get_as_string(content)
        LOG.debug("Openstack network config: %s" % content)

        return debiface.parse(content)

    def get_admin_password(self):
        meta_data = self._get_meta_data()
        meta = meta_data.get('meta')

        if meta and 'admin_pass' in meta:
            password = meta['admin_pass']
        elif 'admin_pass' in meta_data:
            password = meta_data['admin_pass']
        else:
            password = None

        return password

    def get_client_auth_certs(self):
        """Gather all unique certificates found among the metadata.

        If there are no certificates under "meta" or "keys" field,
        then try looking into user-data for this kind of information.
        """
        certs = []
        meta_data = self._get_meta_data()

        meta = meta_data.get("meta")
        if meta:
            cert_data_list = []
            idx = 0
            while True:
                # Chunking is necessary as metadata items can be
                # max. 255 chars long.
                cert_chunk = meta.get("admin_cert%d" % idx)
                if not cert_chunk:
                    break
                cert_data_list.append(cert_chunk)
                idx += 1
            if cert_data_list:
                # It's a list of strings for sure.
                certs.append("".join(cert_data_list))

        keys = meta_data.get("keys")
        if keys:
            for key_dict in keys:
                if key_dict["type"] == "x509":
                    certs.append(key_dict["data"])

        if not certs:
            # Look if the user_data contains a PEM certificate
            try:
                user_data = self.get_user_data().strip()
                if user_data.startswith(
                        x509constants.PEM_HEADER.encode()):
                    certs.append(encoding.get_as_string(user_data))
            except base.NotExistingMetadataException:
                LOG.debug("user_data metadata not present")

        return list(set((cert.strip() for cert in certs)))
