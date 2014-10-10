hybrid-autosign-puppet
======================

Allow autosign of puppet CSR based on request IP address or preshared-keys

Requirements
------------

- Perl 5+
- Perl Module YAML::Tiny
- Perl Module NetAddr::IP

Install
-------

Installing perl modules on Debian:
```
apt-get install libyaml-tiny-perl libnetaddr-ip-perl
```

Installing perl modules on CentOS
```
yum install perl-YAML-Tiny perl-NetAddr-IP
```

Clone the repo inside puppet folder:
```
cd /etc/puppet/
git clone git@github.com:guzmanbraso/hybrid-autosign-puppet.git
```

Make puppet user owner of everything inside
```
chown puppet.puppet /etc/puppet/hybrid-autosign-puppet/ -R
```

Allow all users to read apache/nginx logs
```
chmod 755 /var/log/apache2
```

Configure
-----------------------

Copy example yaml:
```
cp hybrid-autosign.example.yaml hybrid-autosign.yaml
```

Edit they yaml and configure the full path to the apache accesslog.

To whitelist network blocks edit the file and add all networks inside 'networks_allowed'.

To generate shared keys run (replace shared_key_name with something useful):
```
tr -cd 'a-f0-9' < /dev/urandom | head -c 32 >/etc/puppet/hybrid-autosign-puppet/keys/shared_key_name
```

To enable autosign in puppetmaster edit puppet.conf and inside [master] add the following line:
```
autosign = /etc/puppet/hybrid-autosign-puppet/hybrid-autosign.pl
```

Puppet agents
-------------

To use network whitelisting you don't need to do anything on the agents.
   
To use preshared keys you need to add in the agent /etc/puppet a file named csr_attributes.yaml that looks like this:
```
extension_requests:
  pp_preshared_key: your_key_hash
```
