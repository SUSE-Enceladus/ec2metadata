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
        self.dataCategories = ['dynamic/', 'meta-data/']
        self.token_access = False
        
        if not self._test_connectivity(self.addr, 80):
            msg = 'Could not establish connection to: %s' % self.addr
            raise EC2MetadataError(msg)

        self._resetetaOptsAPIMap()
        self._setMetaOpts()

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

    def _addMetaOpts(self, path):
        """Add meta options available under the current path to the options
           to API map"""
        options = list(self.metaOptsAPIMap.keys())
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
                        self.metaOptsAPIMap[item] = path + item
                    else:
                        self._addMetaOpts(path+item)

    def _get(self, uri):
        url = 'http://%s/%s/%s' % (self.addr, self.api, uri)
        token = None
        data_request = None
        value = b''
        if self.token_access:
            req = urllib.request.Request(
                'http://169.254.169.254/latest/api/token',
                headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
                method='PUT'
            )
            try:
                token = urllib.request.urlopen(req).read().decode()
            except urllib.error.URLError:
                msg = 'Unable to obtain token from metadata server'
                raise EC2MetadataError(msg)
            data_request = urllib.request.Request(
                url,
                headers={'X-aws-ec2-metadata-token': token}
            )
        else:
            data_request = urllib.request.Request(url)
        try:
            value = urllib.request.urlopen(data_request).read()
        except urllib.error.URLError:
            if self.token_access:
                return None
            self.use_token_access()
            self._get(uri)

        return value.decode()

    def _resetetaOptsAPIMap(self):
        """Set options that have special semantics"""
        self.metaOptsAPIMap = {
            'public-keys': 'meta-data/public-keys',
            'user-data': 'user-data'
        }

    def _setMetaOpts(self):
        """Set the metadata options for the current API on this object."""
        for path in self.dataCategories:
            self._addMetaOpts(path)

    def get(self, metaopt):
        """Return value of metaopt"""

        path = self.metaOptsAPIMap.get(metaopt, None)
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

    def getAvailableAPIVersions(self):
        """Return a list of the available API versions"""
        url = 'http://%s/' % self.addr
        req = urllib.request.Request(url)
        value = urllib.request.urlopen(req).read().decode()
        apiVers = value.split('\n')
        return apiVers

    def getMetaOptions(self):
        """Return the available options for the current api version"""
        options = list(self.metaOptsAPIMap.keys())
        options.sort()
        return options

    def setAPIVersion(self, apiVersion=None):
        """Set the API version to use for the query"""
        if not apiVersion:
            # Nothing to do
            return self.api
        url = 'http://%s' % self.addr
        req = urllib.request.Request(url)
        availableAPIs = urllib.request.urlopen(req).read().decode().split('\n')
        if apiVersion not in availableAPIs:
            msg = 'Requested API version "%s" not available' % apiVersion
            raise EC2MetadataError(msg)
        self.api = apiVersion
        self._resetetaOptsAPIMap()
        self._setMetaOpts()

    def use_token_access(self):
        """Use token based access to retrieve the metadata information. This
           supports IMDSv2"""
        self.token_access = True
