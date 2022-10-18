Coercive Utility Browser
========================

BETA Simple browser detection utility

Get
---
```
composer require coercive/browser
```

Basic Browser Options
---------------------
```php
use Coercive\Utility\Browser

# Load instance
$browser = new Browser();

# Examples
echo $browser->browser()['name']
echo $browser->browser()['version']
echo $browser->os()
echo $browser->getAGENT()
echo $browser->getIP()

if($browser->mobile()) {}

if($browser->isClientIpInRange('range', /* current */)) {}
if($browser->isClientIpInRange('range', 'ip')) {}

# Mobile_Detect
# https://github.com/serbanghita/Mobile-Detect
$oBrowser->Mobile_Detect()
```


Basic Ip Options
-----------------
```php
use Coercive\Utility\Browser

# Load instance
$ip = new Ip();

# Validate ip / cidr
if($ip->check('127.0.0.1')) {}
if($ip->check('127.0.0.1/32', true)) {}

# Cidr in range infos (start, end, subnet, wildcard, count...)
echo '<pre>';
var_dump($ip->cidrToRange('127.0.0.1/32'));
echo '</pre>';

# List all ips in range
echo '<pre>';
var_dump($ip->cidrToFullRange('127.0.0.1/32'));
echo '</pre>';

# Checking if a given ip belongs to given cidr list
if($ip->isInRange('127.0.0.1', ['127.0.0.1/27','127.0.0.1/64'])) {}
```