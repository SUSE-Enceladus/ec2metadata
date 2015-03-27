#
# spec file for package python-ec2metadata
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


%define upstream_name ec2metadata
Name:           python-ec2metadata
Version:        1.5.2
Release:        0
Summary:        Collect instance metadata in EC2
License:        GPL-3.0+
Group:          System/Management
Url:            https://github.com/rjschwei/ec2metadata/releases
Source0:        %{upstream_name}-%{version}.tar.gz
Requires:       python
BuildRequires:  python-setuptools
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%if 0%{?suse_version} && 0%{?suse_version} <= 1110
%{!?python_sitelib: %global python_sitelib %(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%else
BuildArch:      noarch
%endif

%description
Collect instance meta data in Amazon Compute CLoud instances

%prep
%setup -q -n %{upstream_name}-%{version}

%build
python setup.py build

%install
python setup.py install --prefix=%{_prefix} --root=%{buildroot}

%files
%defattr(-,root,root,-)
%doc COPYING
%dir %{python_sitelib}/%{upstream_name}
%dir %{python_sitelib}/%{upstream_name}-%{version}-py%{py_ver}.egg-info
%{_bindir}/*
%{python_sitelib}/%{upstream_name}/*
%{python_sitelib}/*egg-info/*

%changelog
