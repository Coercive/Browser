<?php
namespace Coercive\Utility\Browser;

use GMP;
use InvalidArgumentException;
use function PHPUnit\Framework\isNumeric;

/**
 * Class Ip
 *
 * @package		Coercive\Utility\Browser
 * @link		https://github.com/Coercive/browser
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2024 Anthony Moral
 * @license 	MIT
 */
class Ip
{
	/**
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 */
	const PATTERN_IPV4_CIDR = '`^(?:((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))\.((?:0)|(?:2(?:(?:[0-4][0-9])|(?:5[0-5])))|(?:1?[0-9]{1,2}))(?:/((?:(?:0)|(?:3[0-2])|(?:[1-2]?[0-9]))))?)$`';

	/**
	 * @source https://www.regextester.com/93988
	 * @author anonymous
	 */
	const PATTERN_IPV6_CIDR = '`^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$`';

	/** @var string SERVER: REMOTE_ADDR entry */
	private string $_REMOTE_ADDR;

	/** @var string SERVER: HTTP_X_FORWARDED_FOR entry */
	private string $_HTTP_X_FORWARDED_FOR;

	/** @var string[] */
	private array $trustedProxies = [];

	/**
	 * Convert an IPv6 address to its numeric representation using GMP.
	 *
	 * @param string $ipv6 The IPv6 address.
	 * @return GMP The numeric representation of the IPv6 address.
	 * @throws InvalidArgumentException
	 */
	private function ipv6ToGmp(string $ipv6): GMP
	{
		$bin = inet_pton($ipv6);
		if ($bin === false) {
			throw new InvalidArgumentException("Invalid IPv6 address: $ipv6");
		}
		return gmp_init(bin2hex($bin), 16);
	}

	/**
	 * Convert a numeric representation of an IPv6 address back to its string representation.
	 *
	 * @param GMP $numericIp The numeric representation of the IPv6 address.
	 * @return string The string representation of the IPv6 address.
	 */
	private function gmpToIpv6(GMP $numericIp): string
	{
		$hex = gmp_strval($numericIp, 16);
		$hex = str_pad($hex, 32, '0', STR_PAD_LEFT);
		$bin = hex2bin($hex);
		return inet_ntop($bin);
	}

	/**
	 * Ip constructor.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->_REMOTE_ADDR = (string) filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$this->_HTTP_X_FORWARDED_FOR = (string) filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	}

	/**
	 * @param string $ip
	 * @return $this
	 */
	public function setRemoteAddress(string $ip): self
	{
		$this->_REMOTE_ADDR = $ip;
		return $this;
	}

	/**
	 * @param string $ip
	 * @return $this
	 */
	public function setForwardedAddress(string $ip): self
	{
		$this->_HTTP_X_FORWARDED_FOR = $ip;
		return $this;
	}

	/**
	 * @param array $ips
	 * @return $this
	 */
	public function setTrustedProxies(array $ips): self
	{
        $this->trustedProxies = [];
        foreach ($ips as $ip) {
            if($this->check($ip)) {
                $this->trustedProxies[] = $ip;
            }
        }
		return $this;
	}

    /**
     * @return string[]
     */
    public function getTrustedProxies(): array
    {
        return $this->trustedProxies;
    }

    /**
     * @param array $ips
     * @param bool $ipv4 [optional]
     * @param bool $ipv6 [optional]
     * @return array
     */
    public function clean(array $ips, bool $ipv4 = true, bool $ipv6 = true): array
    {
        $list = [];
        foreach ($ips as $ip) {
            if($ipv4 && $ipv6) {
                if($this->check($ip)) {
                    $list[] = $ip;
                }
                continue;
            }
            if($ipv4) {
                if($this->isIPv4($ip)) {
                    $list[] = $ip;
                }
                continue;
            }
            if($ipv6) {
                if($this->isIPv6($ip)) {
                    $list[] = $ip;
                }
            }
        }
        return array_unique($list);
    }

	/**
	 * @param string $ip
	 * @return bool
	 */
	public function isIPv4(string $ip): bool
	{
		return (bool) preg_match(self::PATTERN_IPV4_CIDR, $ip);
	}

	/**
	 * @param string $ip
	 * @return bool
	 */
	public function isIPv6(string $ip): bool
	{
		if($this->isMappedIPv6($ip)) {
			$ip = substr($ip, 7);
			return $this->isIPv4($ip);
		}
		return (bool) preg_match(self::PATTERN_IPV6_CIDR, $ip);
	}

	/**
	 *  Checks if an IPv6 address is an IPv4-mapped IPv6 address.
	 *
	 *  IPv4-mapped IPv6 addresses are IPv6 addresses that start with "::ffff:"
	 *  and contain an IPv4 address at the end. This allows IPv6-only systems
	 *  to represent IPv4 addresses.
	 *
	 *  Examples:
	 *    ::ffff:192.168.0.1  => true
	 *    2001:db8::1          => false
	 *
	 * @param string $ip
	 * @return bool
	 */
	public function isMappedIPv6(string $ip): bool
	{
		return 0 === strpos($ip, '::ffff:');
	}

	/**
	 * @param string $ip
	 * @return bool
	 */
	public function hasCIDR(string $ip): bool
	{
		return false !== strpos($ip, '/');
	}

	/**
	 * Validate IPV4 or CIDR
	 *
	 * @param string $ip
	 * @param bool $cidr [optional]
	 * @return bool
	 */
	public function check(string $ip, bool $cidr = false): bool
	{
		$hasCidr = $this->hasCIDR($ip);
		if($cidr && !$hasCidr) {
			return false;
		}
		if($hasCidr) {
			[$ip, $prefix] = explode('/', $ip, 2);
			if (!preg_match('/^\d{1,3}$/', $prefix)) {
				return false;
			}
			$prefix = (int) $prefix;
			if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
				return $prefix >= 0 && $prefix <= 32;
			}
			if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				return $prefix >= 0 && $prefix <= 128;
			}
			return false;
		}
		return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6);
	}

	/**
	 * Get current client ip
	 *
	 * @param bool $deep [optional]
	 * @return string
	 */
	public function getIp(bool $deep = false): string
	{
		if ($this->_HTTP_X_FORWARDED_FOR && $this->trustedProxies && $this->isInRange($this->_REMOTE_ADDR, $this->trustedProxies)) {
            $ips = array_map('trim', explode(',', $this->_HTTP_X_FORWARDED_FOR));
            foreach ($ips as $ip) {
                if(!$deep) {
                    return (string) filter_var($ip, FILTER_VALIDATE_IP);
                }
            }
            if($deep && !empty($ip)) {
                return (string) filter_var($ip, FILTER_VALIDATE_IP);
            }
            return '';
		}
		return (string) filter_var($this->_REMOTE_ADDR, FILTER_VALIDATE_IP);
	}

	/**
	 * Check if the given ipv4 is between given range
	 *
	 * @param string $ipv4 - IPV4 format : 127.0.0.1
	 * @param string $startIP - IPV4 format : 127.0.0.1
	 * @param string $endIP - IPV4 format : 127.0.0.1
	 * @return bool
	 */
	public function isBetweenIPv4(string $ipv4, string $startIP, string $endIP): bool
	{
		if($this->hasCIDR($ipv4)) {
			$range = $this->cidrToRange($ipv4);
			$ipStart = $range['ip_min_dec'] ?? false;
			$ipEnd = $range['ip_max_dec'] ?? false;
		}
		else {
			$ipStart = $ipEnd = ip2long($ipv4);
			if ($ipStart === false) {
				throw new InvalidArgumentException("Invalid IPv4 address format.");
			}
		}

		$rangeStart = ip2long($startIP);
		$rangeEnd = ip2long($endIP);
		if ($rangeStart === false) {
			throw new InvalidArgumentException("Invalid starting IPv4 address format.");
		}
		if ($rangeEnd === false) {
			throw new InvalidArgumentException("Invalid ending IPv4 address format.");
		}

		return ($ipStart >= $rangeStart && $ipEnd <= $rangeEnd);
	}

	/**
	 * Check if a given IPv6 address is within a specified IPv6 range.
	 *
	 * @param string $ip The IPv6 address to check.
	 * @param string $startIP The starting IPv6 address of the range.
	 * @param string $endIP The ending IPv6 address of the range.
	 * @return bool True if the IP is within the range, False otherwise.
	 */
	public function isBetweenIPv6(string $ip, string $startIP, string $endIP): bool
	{
		$ipNumeric = $this->ipv6ToGmp($ip);
		$startNumeric = $this->ipv6ToGmp($startIP);
		$endNumeric = $this->ipv6ToGmp($endIP);

		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The IP address format is invalid.");
		}
		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}
		if(!$this->isIPv6($endIP) || !$this->check($endIP)) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		$start = $this->ipv6ToGmp($startIP);
		$end = $this->ipv6ToGmp($endIP);
		if (gmp_cmp($start, $end) > 0) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		return gmp_cmp($ipNumeric, $startNumeric) >= 0 && gmp_cmp($ipNumeric, $endNumeric) <= 0;
	}

	/**
	 * Check if the given ipv4 is between given range
	 *
	 * @param string $ip
	 * @param string $startIP
	 * @param string $endIP
	 * @return bool
	 */
	public function isBetween(string $ip, string $startIP, string $endIP): bool
	{
		if($this->isIPv6($ip) && $this->isIPv6($startIP) && $this->isIPv6($endIP)) {
			return $this->isBetweenIPv6($ip, $startIP, $endIP);
		}
		elseif($this->isIPv4($ip) && $this->isIPv4($startIP) && $this->isIPv4($endIP)) {
			return $this->isBetweenIPv4($ip, $startIP, $endIP);
		}
		else {
			return false;
		}
	}

    /**
     * @param string $ip Ipv4 or Ipv6 or Cidr Ipv6
     * @param array $cidrs List of Ipv4 or Ipv6
     * @return bool
     */
    public function isInRange(string $ip, array $cidrs): bool
    {
        if(!$ip || !$cidrs) {
            return false;
        }
        if($this->isIPv4($ip)) {
            return $this->isInRangeIPv4($ip, $this->clean($cidrs, true, false));
        }
        elseif ($this->isIPv6($ip)) {
            return $this->isInRangeIPv6($ip, $this->clean($cidrs, false, true));
        }
        else {
            return false;
        }
    }

	/**
	 * Check if the given ipv4 belongs to given list of cidr
	 *
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 *
	 * @param string $ipv4 - IPV4 format : 127.0.0.1
	 * @param string[] $cidrs - List of IP/CIDR netmask : 127.0.0.0/24
	 * @return bool
	 */
	private function isInRangeIPv4(string $ipv4, array $cidrs): bool
	{
		# Convert to dec
		if(!$ip = ip2long($ipv4)) {
			return false;
		}

		# This code is checking if a given ip belongs to given cidr list
		foreach($cidrs as $cidr) {
			if(!$range = $this->cidr2LongIntRange($cidr)) {
				continue;
			}
			if($ip >= $range[0] && $ip <= $range[1]) {
				return true;
			}
		}
		return false;
	}

    /**
     * @param string $ipv6
     * @param array $cidrs
     * @return bool
     */
    private function isInRangeIPv6(string $ipv6, array $cidrs): bool
    {
        $ip = $this->parseIpv6Cidr($ipv6);

        foreach ($cidrs as $cidr) {
            $range = $this->parseIpv6Cidr($cidr);

            // Overlap rule: Two prefixes overlap if their first min(prefixA, prefixB) bits are equal.
            $minMask = min($ip['mask'], $range['mask']);

            if ($this->isIPv6Overlap($ip['bin'], $range['bin'], $minMask)) {
                return true;
            }
        }

        return false;

    }

    /**
     * @param string $inputBin
     * @param string $rangeBin
     * @param int $minMask
     * @return bool
     */
    private function isIPv6Overlap(string $inputBin, string $rangeBin, int $minMask): bool
    {
        # Full range
        if($minMask === 0) {
            return true;
        }

        # input is a single IPv6 (/128 or unspecified) -> check if IP is inside range
        if($minMask === 128) {
            return hash_equals($inputBin, $rangeBin);
        }

        # input is IPv6 CIDR -> check whether the two CIDRs overlap (intersection not empty)
        $fullBytes = intdiv($minMask, 8);
        $remBits = $minMask % 8;

        // Compare full bytes
        if ($fullBytes > 0) {
            // substr_compare is fast and avoids large string ops
            if (substr_compare($inputBin, $rangeBin, 0, $fullBytes) !== 0) {
                return false;
            }
        }

        // Compare remaining bits in next byte
        if ($remBits > 0) {
            $mask = (0xFF << (8 - $remBits)) & 0xFF;

            $aByte = ord($inputBin[$fullBytes]) & $mask;
            $bByte = ord($rangeBin[$fullBytes]) & $mask;

            if ($aByte !== $bByte) {
                return false;
            }
        }

        return true;
    }

	/**
	 * Convert CIDR to RANGE IP
	 *
	 * Same as ->cidrToRange() but give ONLY int notation
	 *
	 * @param string $ipv4
	 * @return int[]
	 */
	public function cidr2LongIntRange(string $ipv4): array
	{
		# Validate IP first
		if(!$this->check($ipv4)) {
			return [];
		}

		# Add forgotten 32 mask
		if (!strpos($ipv4,'/')) {
			$ipv4 .= '/32';
		}

		# Separate start ip and mask
		list($ip, $suffix) = explode('/', $ipv4);
		$ip = ip2long($ip);
		$mask = -1 << (32 - $suffix);

		# Apply mask, calculate end range
		$network = $ip & $mask;
		$broadcast = $network + ~$mask;
		return [$network, $broadcast];
	}

	/**
	 * Convert CIDR to RANGE IP
	 *
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 *
	 * @param $ipv4
	 * @return array{ip_min_dec: int, ip_max_dec: int, ip_min: string, ip_max: string, subnet: string, wildcard: string, count: int}
	 */
	public function cidrToRange(string $ipv4): array
	{
		# Validate IP first
		if(!$this->check($ipv4)) {
			return [];
		}

		# Convert CIDR
		if ($pos = strpos($ipv4,'/')) {
			$n_ip = (1<<(32-substr($ipv4,1 + $pos))) -1;
			$ip_dec = ip2long(substr($ipv4,0, $pos));
		}

		# Ip v4 only
		else {
			$n_ip = 0;
			$ip_dec = ip2long($ipv4);
		}

		if ($ip_dec === false) {
			throw new InvalidArgumentException("Invalid IPv4 address format.");
		}

		# Define range
		$ip_min = $ip_dec & ~$n_ip;
		$ip_max = $ip_min + $n_ip;

		# Different formats
		return [
			'ip_min_dec' => $ip_min,
			'ip_max_dec' => $ip_max,
			'ip_min' => long2ip($ip_min),
			'ip_max' => long2ip($ip_max),
			'subnet' => long2ip(~$n_ip),
			'wildcard' => long2ip($n_ip),
			'count' => ++$n_ip,
		];
	}

	/**
	 * Convert CIDR to FULL RANGE IP
	 *
	 * @source https://stackoverflow.com/questions/4931721/getting-list-ips-from-cidr-notation-in-php#answer-42269989
	 * @author Php'RegEx https://stackoverflow.com/users/7558876/phpregex
	 *
	 * @param string $ipv4
	 * @return array
	 */
	public function cidrToFullRange(string $ipv4): array
	{
		# Calculate range infos
		$range = $this->cidrToRange($ipv4);
		if(!$range) {
			return [];
		}

		# Increment list
		$list = [];
		for($ip_dec = $range['ip_min_dec']; $ip_dec <= $range['ip_max_dec']; $ip_dec++) {
			$list[$ip_dec] = long2ip($ip_dec);
		}
		return $list;
	}

	/**
	 * Merge IPv4 ranges (string representation)
	 *
	 * @param array $ranges
	 * @return array
	 */
	public function mergeIpRanges(array $ranges): array
	{
		$longs = [];
		foreach ($ranges as $range) {
			$longs[] = [ip2long($range[0]), ip2long($range[1])];
		}

		$ranges = [];
		foreach ($this->mergeIpLongIntRanges($longs) as $range) {
			$ranges[] = [long2ip($range[0]), long2ip($range[1])];
		}
		return $ranges;
	}

	/**
	 * Merge IPv4 ranges (int representation)
	 *
	 * @param array $longIntRanges INT ! convert IP with ip2long before
	 * @return array
	 */
	public function mergeIpLongIntRanges(array $longIntRanges): array
	{
		# Order ASC
		usort($longIntRanges, function($a, $b) {
			return $a[0] - $b[0];
		});

		$merged = [];
		$current = $longIntRanges[0];
		foreach ($longIntRanges as $range) {
			# MERGE : if the ranges are contiguous or overlapping
			if ($range[0] <= $current[1] + 1) {
				$current[1] = max($current[1], $range[1]);
			}
			# NEXT : otherwise, store the current range and start a new one
			else {
				$merged[] = $current;
				$current = $range;
			}
		}
		# Add last range
		$merged[] = $current;

		return $merged;
	}

	/**
	 * Check if IP is in given domain list - with optional reverse check
	 *
	 * @param string $ip
	 * @param array $domains
	 * @param bool $reverse [optional]
	 * @return bool
	 */
	public function isIpMatchDomains(string $ip, array $domains, bool $reverse = false): bool
	{
		# Get hostname
		$hostname = gethostbyaddr($ip);
		if(!$hostname) {
			return false;
		}

		# Detect if in domains list
		$founded = false;
		foreach ($domains as $domain) {
			if (preg_match('`' . preg_quote($domain, '$`') . '`', $hostname)) {
				$founded = true;
				break;
			}
		}
		if(!$founded) {
			return false;
		}

		# Reverse match
		if(!$reverse) {
			return true;
		}
		$hosts = gethostbynamel($hostname) ?: [];
		foreach ($hosts as $host) {
			if($host === $ip) {
				return true;
			}
		}
		return false;
	}



	/**
	 * Convert an IP range to a list of CIDR blocks.
	 *
	 * Use BCMath/GMP to avoid PHP integer limits.
	 *
	 * @param string $startIP The starting IPv6 address of the range.
	 * @param string $endIP The ending IPv6 address of the range.
	 * @return array The list of CIDR blocks representing the IP range.
	 * @throws InvalidArgumentException
 	 */
	public function rangeToCIDRIPv6(string $startIP, string $endIP): array
	{
		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}
		if(!$this->isIPv6($endIP) || !$this->check($endIP)) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}
		if ($startIP === '::' && $endIP === 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') {
			return ['::/0'];
		}

		# Convert hexadecimal to large decimal numbers (string)
		$start = $this->ipv6ToGmp($startIP);
		$end = $this->ipv6ToGmp($endIP);

		$start_dec = gmp_strval($start);
		$end_dec = gmp_strval($end);
		if (bccomp($start_dec, $end_dec) > 0) {
			throw new InvalidArgumentException("The start address is greater than the end address.");
		}

		$cidr_list = [];
		$current_ip_dec = $start_dec;

		# CIDR decomposition algorithm
		while (bccomp($current_ip_dec, $end_dec) <= 0) {

			# Find the smallest power of 2 by which the current address is divisible
			for ($p = 1; $p <= 128; $p++) {
				# $power_of_two = pow(2, $p) - Use BCMath/GMP to avoid PHP integer limits
				$power_of_two = bcpow('2', $p);

				# Check if range ends in block
				# $next_ip_in_block = $current_ip_dec + $power_of_two - Use BCMath/GMP to avoid PHP integer limits
				$next_ip_in_block = bcadd($current_ip_dec, $power_of_two);

				# The next range exceeds the end of the requested range
				if (bccomp($next_ip_in_block, $end_dec) > 0 && bccomp($next_ip_in_block, bcadd($end_dec, '1')) > 0) {
					# The ideal mask is the one from the previous round
					$max_prefix = 128 - ($p - 1);
					break;
				}

				# Check if the current address is divisible by $power_of_two
				if (bccomp(bcmod($current_ip_dec, $power_of_two), '0') !== 0) {
					# The address is not aligned.
					# The ideal mask is the one from the previous round.
					$max_prefix = 128 - ($p - 1);
					break;
				}

				# The smallest mask so far (the largest block)
				$max_prefix = 128 - $p;
			}

			# Calculate block size (2^(128 - max_prefix))
			$block_size = bcpow('2', 128 - $max_prefix);

			# Converting block start IP to CIDR format
			$ip_formatted = $this->gmpToIpv6(gmp_init($current_ip_dec));

			$cidr_list[] = $ip_formatted . '/' . $max_prefix;

			# Advance the current address to the start of the next block
			$current_ip_dec = bcadd($current_ip_dec, $block_size);
		}

		return $cidr_list;
	}

	/**
	 * Convert a range of IP addresses to CIDR notation.
	 *
	 * @param string $start [OR INT REPRESENTATION] The starting IP address of the range.
	 * @param string $end [OR INT REPRESENTATION] The ending IP address of the range.
	 * @return array An array of CIDR notations.
	 * @throws InvalidArgumentException
	 */
	public function rangeToCIDRIPv4(string $start, string $end): array
	{
		if(strpos($start, '.')) {
			$start = ip2long($start);
			if ($start === false) {
				throw new InvalidArgumentException('The starting IP address format is invalid.');
			}
		}
		else {
			$start = intval($start);
		}

		if(strpos($end, '.')) {
			$end = ip2long($end);
			if ($end === false) {
				throw new InvalidArgumentException('The ending IP address format is invalid.');
			}
		}
		else {
			$end = intval($end);
		}

		# Convert ip2long signed integer to an unsigned integer (32 bits), using an AND mask with 0xFFFFFFFF
		# to ensure compatibility with 64-bit platforms (and to handle addresses > 127.255.255.255).
		$uStart = $start & 0xFFFFFFFF;
		$uEnd = $end & 0xFFFFFFFF;
		if ($uStart > $uEnd) {
			throw new InvalidArgumentException('The starting IP address must be less than or equal to the ending IP address.');
		}

		$cidr_list = [];
		$current_ip_int = $uStart;

		# Greedy CIDR decomposition algorithm
		while ($current_ip_int <= $uEnd) {

			# Determine the largest possible mask. We're looking for the largest aligned block
			# that doesn't extend beyond the end of the range ($uEnd).
			for ($i = 0; $i <= 32; $i++) {
				$block_size = 1 << $i;
				$prefix = 32 - $i;

				# The current IP must be aligned with this block.
				if (($current_ip_int & ($block_size - 1)) !== 0

					# The end of the block must not exceed $uEnd.
					|| ($current_ip_int + $block_size - 1) > $uEnd) {

					# If the IP is not aligned, the previous mask is the largest valid one.
					$max_prefix = 32 - ($i - 1);
					break;
				}

				# Continue to look for a larger block.
				$max_prefix = $prefix;
			}

			# Calculate the size of the optimal block found
			$block_size_optimal = 1 << (32 - $max_prefix);

			# Converting block start IP to CIDR format
			$ip_formatted = long2ip($current_ip_int);
			$cidr_list[] = $ip_formatted . '/' . $max_prefix;

			# Advance the current address to the start of the next block
			$current_ip_int += $block_size_optimal;
		}

		return $cidr_list;
	}

	/**
	 * Convert a range of IP addresses to CIDR notation.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return array An array of CIDR notations.
	 */
	public function rangeToCIDR(string $startIP, string $endIP): array
	{
		if($this->isIPv6($startIP) && $this->isIPv6($endIP)) {
			return $this->rangeToCIDRIPv6($startIP, $endIP);
		}
		elseif($this->isIPv4($startIP) && $this->isIPv4($endIP)) {
			return $this->rangeToCIDRIPv4($startIP, $endIP);
		}
		else {
			throw new InvalidArgumentException("The two IP addresses provided must be of the same type.");
		}
	}

	/**
	 * Calculate the number of IP addresses in a given CIDR block.
	 *
	 * @param string $cidr The CIDR block (e.g., "192.168.1.0/24").
	 * @return string The number of IP addresses in the CIDR block. STRING BECAUSE OF LENGTH
	 */
	public function countIPsInCIDR(string $cidr): string
	{
		$mask = explode('/', $cidr)[1] ?? null;
		if(null === $mask) {
			return 1;
		}
		elseif($this->isIPv4($cidr)) {
			if ($mask < 0 || $mask > 32) {
				throw new InvalidArgumentException("Invalid IPv4 mask: $mask");
			}
			return 1 << (32 - (int) $mask);
		}
		elseif($this->isIPv6($cidr)) {
			if ($mask < 0 || $mask > 128) {
				throw new InvalidArgumentException("Invalid IPv6 mask: $mask");
			}
			return gmp_strval(gmp_pow(2, 128 - (int) $mask));
		}
		else {
			throw new InvalidArgumentException("Invalid CIDR: $cidr");
		}
	}

	/**
	 * Calculate the number of IP v4 addresses in a given IP range.
	 *
	 * @param string $start The starting IP address of the range.
	 * @param string $end The ending IP address of the range.
	 * @return int The number of IP addresses in the range.
	 */
	public function countIPv4sInRange(string $start, string $end): int
	{
		if(filter_var($start, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$start = ip2long($start);
			if ($start === false) {
				throw new InvalidArgumentException('The starting IP address format is invalid.');
			}
		}
		elseif(is_numeric($start)) {
			$start = intval($start);
			if ($start < 0 || $start > 4294967295) {
				throw new InvalidArgumentException('The starting IP address is invalid.');
			}
		}
		else {
			throw new InvalidArgumentException('Unexpected starting IP format');
		}

		if(filter_var($end, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$end = ip2long($end);
			if ($end === false) {
				throw new InvalidArgumentException('The ending IP address format is invalid.');
			}
		}
		elseif(is_numeric($end)) {
			$end = intval($end);
			if ($end < 0 || $end > 4294967295) {
				throw new InvalidArgumentException('The ending IP address is invalid.');
			}
		}
		else {
			throw new InvalidArgumentException('Unexpected ending IP format');
		}

		if ($start > $end) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		return $end - $start + 1;
	}

	/**
	 * Calculate the number of IP addresses in a given IPv6 range.
	 *
	 * @param string $startIP The starting IPv6 address of the range.
	 * @param string $endIP The ending IPv6 address of the range.
	 * @return string The number of IP addresses in the range. STRING BECAUSE OF LENGTH
	 */
	public function countIPv6sInRange(string $startIP, string $endIP): string
	{
		if(!$this->isIPv6($startIP) || !$this->check($startIP)) {
			throw new InvalidArgumentException("The starting IP address format is invalid.");
		}
		if(!$this->isIPv6($endIP) || !$this->check($endIP)) {
			throw new InvalidArgumentException("The ending IP address format is invalid.");
		}

		$start = $this->ipv6ToGmp($startIP);
		$end = $this->ipv6ToGmp($endIP);
		if (gmp_cmp($start, $end) > 0) {
			throw new InvalidArgumentException("The starting IP address must be less than or equal to the ending IP address.");
		}

		return gmp_strval(gmp_add(gmp_sub($end, $start), 1));
	}

	/**
	 * Calculate the number of IP v4 or v6 addresses in a given IP range.
	 *
	 * @param string $startIP The starting IP address of the range.
	 * @param string $endIP The ending IP address of the range.
	 * @return string The number of IP addresses in the range. STRING BECAUSE OF LENGTH FOR IPV6 ADDRESSES
	 */
	public function countIPsInRange(string $startIP, string $endIP): string
	{
		if($this->isIPv6($startIP) && $this->isIPv6($endIP)) {
			return $this->countIPv6sInRange($startIP, $endIP);
		}
		elseif($this->isIPv4($startIP) && $this->isIPv4($endIP)) {
			return $this->countIPv4sInRange($startIP, $endIP);
		}
		else {
			throw new InvalidArgumentException("The two IP addresses provided must be of the same type.");
		}
	}

	/**
	 * Remove duplicates and merge contiguous ranges, returning an optimized list of CIDRs.
	 *
	 * @param array $cidrs
	 * @return array
	 */
	public function optimizeCidrList(array $cidrs): array
	{
		# Convert CIDRS into IP ranges (long int representation)
		$ranges = [];
		foreach ($cidrs as $cidr) {
			$ranges[] = $this->cidr2LongIntRange($cidr);
		}

		# Merge contiguous and overlapping ranges
		$merged = $this->mergeIpLongIntRanges($ranges);

		# Convert merged ranges into CIDRS
		$optimized = [];
		foreach ($merged as $range) {
			$optimized = array_merge($optimized, $this->rangeToCIDRIPv4($range[0], $range[1]));
		}
		return $optimized;
	}

	/**
	 * Order an IPv4 array list
	 *
	 * @param array $ipv4s
	 * @param string $order [optional] asc|desc
	 * @return array
	 */
	static public function orderby(array $ipv4s, string $order = 'asc'): array
	{
		if($order === 'asc') {
			uasort($ipv4s, function($a, $b) {
				$longA = ip2long($a);
				$longB = ip2long($b);
				if ($longA === false && $longB === false) return 0;
				if ($longA === false) return 1;
				if ($longB === false) return -1;
				return $longA <=> $longB;
			});
		}
		elseif($order === 'desc') {
			uasort($ipv4s, function($a, $b) {
				$longA = ip2long($a);
				$longB = ip2long($b);
				if ($longA === false && $longB === false) return 0;
				if ($longA === false) return 1;
				if ($longB === false) return -1;
				return $longB <=> $longA;
			});
		}
		return $ipv4s;
	}

	/**
	 * Get ASN from whois.cymru.com
	 *
	 * @param string $ip
	 * @return int
	 */
	public function getASN(string $ip): int
	{
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			return 0;
		}

		$cmd = "whois -h whois.cymru.com ' -v $ip'";
		exec($cmd, $output, $return_var);
		if ($return_var !== 0 || count($output) < 2) {
			return 0;
		}

		$parts = preg_split('/\s+/', trim($output[1]));
		if (count($parts) >= 1) {
			return intval($parts[0] ?? 0);
		}
		return 0;
	}

	/**
	 * GET ASN CIDRS from whois.radb.net (uniq)
	 *
	 * @param int $asn
	 * @param bool $ipv4 [optional]
	 * @param bool $ipv6 [optional]
	 * @return array
	 */
	public function getCidrsFromASN(int $asn, bool $ipv4 = true, bool $ipv6 = true): array
	{
		if (!$asn || !$ipv4 && !$ipv6) {
			return [];
		}

		$cmd = "whois -h whois.radb.net -- '-i origin AS$asn' | grep ^route";
		exec($cmd, $output, $return_var);
		if ($return_var !== 0 || !$output) {
			return [];
		}

		$type = 'route';
		if($ipv6) {
			$type .= '6';
		}
		if($ipv4 && $ipv6) {
			$type .= '?';
		}
		$ranges = [];
		foreach ($output as $line) {
			if (preg_match('`^' . $type . ':\s+([a-f\d./:]+)`', $line, $match)) {
				$ranges[] = $match[1];
			}
		}
		return array_unique($ranges);
	}

	/**
	 * GET ASN ip ranges (uniq)
	 *
	 * @param int $asn
	 * @return array
	 */
	public function getRangesFromASN(int $asn): array
	{
		$cidrs = $this->getCidrsFromASN($asn);
		if(!$cidrs) {
			return [];
		}

		$ranges = [];
		foreach ($cidrs as $cidr) {
			$range = $this->cidrToRange($cidr);
			$ranges[] = [
				$range['ip_min'],
				$range['ip_max']
			];
		}
		return $this->mergeIpRanges($ranges);
	}

    /**
     * @alias inet_pton
     *
     * @param string $ip
     * @return string
     * @throws InvalidArgumentException
     */
    public function ipToBin(string $ip): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            throw new InvalidArgumentException('Invalid IP address : ' . $ip);
        }
        return $bin;
    }

    /**
     * @alias inet_ntop
     *
     * @param string $bin
     * @return string
     * @throws InvalidArgumentException
     */
    public function binToIp(string $bin): string
    {
        $ip = @inet_ntop($bin);
        if ($ip === false) {
            throw new InvalidArgumentException('Invalid IP binary');
        }
        return $ip;
    }

    /**
     * @alias strcmp
     * Compare two binary IP addresses (of the same length).
     * Returns <0 if $a < $b, 0 if equal, >0 if $a > $b
     *
     * @param string $a
     * @param string $b
     * @return int
     */
    public function cmpBin(string $a, string $b): int
    {
        return strcmp($a, $b);
    }

    /**
     * Increment a binary (big endian) IP address.
     *
     * @param string $bin
     * @return string
     */
    public function incBin(string $bin): string
    {
        $len = strlen($bin);
        for ($i = $len - 1; $i >= 0; $i--) {
            $ord = ord($bin[$i]);
            if ($ord < 255) {
                $bin[$i] = chr($ord + 1);
                return $bin;
            }
            $bin[$i] = chr(0);
        }
        return $bin;
    }

    /**
     * Decrements a binary (big endian) IP address.
     *
     * @param string $bin
     * @return string
     */
    public function decBin(string $bin): string
    {
        $len = strlen($bin);
        for ($i = $len - 1; $i >= 0; $i--) {
            $ord = ord($bin[$i]);
            if ($ord > 0) {
                $bin[$i] = chr($ord - 1);
                return $bin;
            }
            $bin[$i] = chr(255);
        }
        return $bin;
    }

    /**
     * @param string $ipv6cidr
     * @return array {ip, bin, mask, port}
     */
    public function parseIpv6Cidr(string $ipv6cidr): array
    {
        // Handle bracketed IPv6 with optional port: [2001:db8::1]:443
        $port = null;
        if (0 === strpos($ipv6cidr, '[') && $end = strpos($ipv6cidr, ']')) {
            $port = substr($ipv6cidr, $end + 2) ?: null;
            $ipv6cidr = substr($ipv6cidr, 1, $end - 1);
        }

        // Split CIDR if present
        $prefix = 128;
        if (strpos($ipv6cidr, '/')) {
            [$addr, $pfx] = explode('/', $ipv6cidr, 2);

            $prefix = (int) $pfx;
            if ($prefix < 0 || $prefix > 128) {
                throw new InvalidArgumentException('Invalid IPv6 prefix: ' . $ipv6cidr);
            }

            $ipv6cidr = $addr;
        }

        // inet_pton returns false on invalid address, esure it's IPv6 (16 bytes). IPv4 would be 4 bytes.
        $bin = @inet_pton($ipv6cidr);
        if ($bin === false || strlen($bin) !== 16) {
            throw new InvalidArgumentException('Invalid IPv6 address: ' . $ipv6cidr);
        }
        return [
            'ip' => $ipv6cidr,
            'bin' => $bin,
            'mask' => $prefix,
            'port' => null === $port ? null : (int) $port,
        ];
    }

    /**
     * Parse textarea content
     *
     * @param string $raw Textarea raw content.
     * @param int|null $version 4, 6 or null (both).
     * @return string[] Ip list
     */
    public function parseStrlist(string $raw, ? int $version = null): array
    {
        $ips = [];

        # Split \n or \r\n
        $lines = preg_split('/\R/', $raw);

        foreach ($lines as $line) {

            $line = trim($line);
            if (!$line || strpos($line, '#') === 0) {
                continue;
            }

            if ($version === 4) {
                $flags = FILTER_FLAG_IPV4;
            }
            elseif ($version === 6) {
                $flags = FILTER_FLAG_IPV6;
            }
            else {
                $flags = 0;
            }

            if ($ip = filter_var($line, FILTER_VALIDATE_IP, ['flags' => $flags])) {
                $ips[$ip] = true;
            }
        }

        return array_keys($ips);
    }

    /**
     * Excludes a series of IP addresses from a range [start, end].
     *
     * @param string $startIp IP starting point of the range (v4 or v6).
     * @param string $endIp IP address at the end of the range.
     * @param string[] $excludeIps IP to exclude (same family as start/end).
     * @return array[] List of remaining ranges:
     * [
     *   ['start' => 'x', 'end' => 'y'],
     *   ...
     * ]
     */
    public function splitRange(string $startIp, string $endIp, array $excludeIps): array
    {
        $startBin = $this->ipToBin($startIp);
        $endBin = $this->ipToBin($endIp);
        if (strlen($startBin) !== strlen($endBin)) {
            throw new InvalidArgumentException('Incorrect ip range');
        }

        # Filter and convert exclude IP list
        $excludeBin = [];
        foreach ($excludeIps as $ip) {
            $bin = $this->ipToBin($ip);
            if (strlen($bin) !== strlen($startBin)) {
                continue;
            }
            if ($this->cmpBin($bin, $startBin) < 0 || $this->cmpBin($bin, $endBin) > 0) {
                continue;
            }
            $excludeBin[] = $bin;
        }
        if (!$excludeBin) {
            return [
                ['start' => $startIp, 'end' => $endIp],
            ];
        }

        # Sorting IPs to exclude in asc order
        usort($excludeBin, [$this, 'cmpBin']);

        $ranges = [];
        $currentStart = $startBin;
        foreach ($excludeBin as $ipBin) {
            # If the excluded IP address is before the currentStart, it has already been "skipped".
            if ($this->cmpBin($ipBin, $currentStart) < 0) {
                continue;
            }

            # If the excluded IP address is after the end, we can stop.
            if ($this->cmpBin($ipBin, $endBin) > 0) {
                break;
            }

            # If the excluded IP address is strictly after currentStart, we have a "full" range between currentStart and ipBin-1
            if ($this->cmpBin($ipBin, $currentStart) > 0) {
                $rangeEnd = $this->decBin($ipBin);

                # Check that the range is valid
                if ($this->cmpBin($rangeEnd, $currentStart) >= 0) {
                    $ranges[] = [
                        'start' => $this->binToIp($currentStart),
                        'end'   => $this->binToIp($rangeEnd),
                    ];
                }
            }

            # Start a new range after the excluded IP address
            $currentStart = $this->incBin($ipBin);
        }

        # Final range after the last excluded IP
        if ($this->cmpBin($currentStart, $endBin) <= 0) {
            $ranges[] = [
                'start' => $this->binToIp($currentStart),
                'end'   => $this->binToIp($endBin),
            ];
        }

        return $ranges;
    }
}