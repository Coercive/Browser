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

$browser = new Browser();
echo $browser->getUserAgent();

$browser->setUserAgent('Custom');
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

# Check if IP is in given domain list - with optional reverse check
if($ip->isIpMatchDomains('127.0.0.1', ['example.domain.com'], true)) {}

# Checking if a given ip belongs to given cidr list
if($ip->isInRange('127.0.0.1', ['127.0.0.1/27','127.0.0.1/64'])) {}
```