# Copyright (c) 2013 Alon Swartz <alon@turnkeylinux.org>
# Copyright (c) 2019 SUSE LLC
#
# This file is part of ec2metadata.
#
# ec2metadata is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ec2metadata is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ec2metadata.  If not, see <http://www.gnu.org/licenses/>.

import time
import urllib.request
import urllib.parse
import urllib.error
import socket


class EC2MetadataError(Exception):
    pass


class EC2Metadata:
    """Class for querying metadata from EC2"""

    def __init__(self, addr='169.254.169.254', api='2008-02-01'):
        self.addr = addr
        self.api = api
        self.data_categories = ['dynamic/', 'meta-data/']
        self.token = ''
        self.token_access = False
        self.token_expiry = int(time.time())

        if not self._test_connectivity(self.addr, 80):
            msg = 'Could not establish connection to: %s' % self.addr
            raise EC2MetadataError(msg)

        self._reset_meta_options_api_map()
        self._set_meta_options()

    @staticmethod
    def _test_connectivity(addr, port):
        for i in range(6):
            s = socket.socket()
            try:
                s.connect((addr, port))
                s.close()
                return True
            except socket.error:
                time.sleep(1)

        return False

    def _add_mata_option(self, path):
        """Add meta options available under the current path to the options
           to API map"""
        options = list(self.meta_options_api_map.keys())
        value = self._get(path)
        if not value:
            return None
        entries = value.split('\n')
        for item in entries:
            if item:
                if item == 'public-keys/':
                    continue
                if item not in options:
                    if item[-1] != '/':
                        self.meta_options_api_map[item] = path + item
                    else:
                        self._add_mata_option(path+item)

    def _create_request(self, url):
        """Create a request object used to access the given URL"""
        request = None
        token_ttl = 100
        if self.token_access:
            # Cut off the decimals, provides a small buffer for time skew
            now = int(time.time())
            if not self.token or now > self.token_expiry:
                self.token_expiry = now + token_ttl
                req = urllib.request.Request(
                    'http://169.254.169.254/latest/api/token',
                    headers={
                        'X-aws-ec2-metadata-token-ttl-seconds': str(token_ttl)
                    },
                    method='PUT'
                )
                try:
                    self.token = urllib.request.urlopen(req).read().decode()
                except urllib.error.URLError:
                    msg = 'Unable to obtain token from metadata server'
                    raise EC2MetadataError(msg)
            request = urllib.request.Request(
                url,
                headers={'X-aws-ec2-metadata-token': self.token}
            )
        else:
            request = urllib.request.Request(url)

        return request

    def _get(self, uri):
        url = 'http://%s/%s/%s' % (self.addr, self.api, uri)
        value = b''
        request = self._create_request(url)
        try:
            value = urllib.request.urlopen(request).read()
        except urllib.error.URLError:
            if self.token_access:
                return None
            self.use_token_access()
            return self._get(uri)

        return value.decode()

    def _reset_meta_options_api_map(self):
        """Set options that have special semantics"""
        self.meta_options_api_map = {
            'public-keys': 'meta-data/public-keys',
            'user-data': 'user-data'
        }

    def _set_meta_options(self):
        """Set the metadata options for the current API on this object."""
        for path in self.data_categories:
            self._add_mata_option(path)

    def get(self, metaopt):
        """Return value of metaopt"""

        path = self.meta_options_api_map.get(metaopt, None)
        if not path:
            raise EC2MetadataError('Unknown metaopt: %s' % metaopt)

        if metaopt == 'public-keys':
            public_keys = []
            data = self._get('meta-data/public-keys')
            if not data:
                return public_keys

            keyids = [line.split('=')[0] for line in data.splitlines()]
            for keyid in keyids:
                uri = 'meta-data/public-keys/%d/openssh-key' % int(keyid)
                public_keys.append(self._get(uri).rstrip())

            return public_keys

        return self._get(path)

    def get_available_api_versions(self):
        """Return a list of the available API versions"""
        url = 'http://%s/' % self.addr
        request = self._create_request(url)
        try:
            value = urllib.request.urlopen(request).read().decode()
        except urllib.error.URLError:
            if self.token_access:
                return []
            self.use_token_access()
            return self.get_available_api_versions()
        apiVers = value.split('\n')
        return apiVers

    def get_meta_data_options(self):
        """Return the available options for the current api version"""
        options = list(self.meta_options_api_map.keys())
        options.sort()
        return options

    def set_api_version(self, api_version=None):
        """Set the API version to use for the query"""
        if not api_version:
            # Nothing to do
            return self.api
        url = 'http://%s' % self.addr
        request = self._create_request(url)
        meta_apis = b''
        try:
            meta_apis = urllib.request.urlopen(request).read()
        except urllib.error.URLError:
            if self.token_access:
                return None
            self.use_token_access()
            return self.set_api_version(api_version)
        available_apis = meta_apis.decode().split('\n')
        if api_version not in available_apis:
            msg = 'Requested API version "%s" not available' % api_version
            raise EC2MetadataError(msg)
        self.api = api_version
        self._reset_meta_options_api_map()
        self._set_meta_options()

    def use_token_access(self):
        """Use token based access to retrieve the metadata information. This
           supports IMDSv2"""
        self.token_access = True
