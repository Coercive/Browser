Coercive Utility Browser
========================

BETA Simple browser detection utility

Get
---
```
composer require coercive/browser
```

Load
----
```php
use Coercive\Utility\Cache

# BETA

$oBrowser = new Browser

echo $oBrowser->browser()['name']
echo $oBrowser->browser()['version']
echo $oBrowser->os()
echo $oBrowser->getAGENT()
echo $oBrowser->getIP()

if($oBrowser->mobile()) {}

if($oBrowser->isClientIpInRange('range', /* current */)) {}
if($oBrowser->isClientIpInRange('range', 'ip')) {}

# Mobile_Detect
# https://github.com/serbanghita/Mobile-Detect
$oBrowser->Mobile_Detect()

ETC...

```