<?php declare(strict_types=1);

use Coercive\Utility\Browser\Ip;
use PHPUnit\Framework\TestCase;

final class IpTest extends TestCase
{
	public function testBasics(): void
	{
		$ip = new Ip;

		$ip->setRemoteAddress('127.0.0.1');
		$ip->setForwardedAddress('::1, 127.0.0.2');

		# Check direct input
		$this->assertSame('127.0.0.1', $ip->getIp());

		# Check proxy
		$this->assertSame('::1', $ip->getIp(['1234', '127.0.0.1']));
		$this->assertSame('127.0.0.2', $ip->getIp(['1234', '127.0.0.1'], true));

		# Check test
		$this->assertFalse($ip->isIPv4('::1'));
		$this->assertTrue($ip->isIPv4('127.0.0.1'));
		$this->assertTrue($ip->isIPv4('127.0.0.1/32'));
		$this->assertFalse($ip->isIPv4('127.0.0.1/33'));

		$this->assertTrue($ip->isMappedIPv6('::ffff:192.168.0.1'));
		$this->assertFalse($ip->isMappedIPv6('2001:db8::1'));

		$this->assertTrue($ip->hasCIDR('127.0.0.1/32'));
		$this->assertFalse($ip->hasCIDR('127.0.0.1'));

		$this->assertTrue($ip->isIPv6('::'));
		$this->assertTrue($ip->isIPv6('::1'));
		$this->assertTrue($ip->isIPv6('0:0:0:0:0:0:0:0'));
		$this->assertTrue($ip->isIPv6('2001:db8::1'));
		$this->assertTrue($ip->isIPv6('2001:0db8:0000:0000:0000:0000:0000:0001'));
		$this->assertTrue($ip->isIPv6('fe80::1ff:fe23:4567:890a'));
		$this->assertTrue($ip->isIPv6('2001:db8:85a3::8a2e:370:7334'));
		$this->assertTrue($ip->isIPv6('FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'));
		$this->assertTrue($ip->isIPv6('2001:DB8::1'));

		$this->assertFalse($ip->isIPv6(''));
		$this->assertFalse($ip->isIPv6('::g'));
		$this->assertFalse($ip->isIPv6('2001:db8:::1'));
		$this->assertFalse($ip->isIPv6('2001:db8::1::1'));
		$this->assertFalse($ip->isIPv6('2001:db8::12345'));
		$this->assertFalse($ip->isIPv6('2001:db8:xyz::1'));
		$this->assertFalse($ip->isIPv6('2001'));
		$this->assertFalse($ip->isIPv6('1:2:3:4:5:6:7:8:9'));

		# Trap: check mapped ipv4
		$this->assertTrue($ip->isIPv6('::ffff:192.168.0.1'));
		$this->assertTrue($ip->isIPv6('::ffff:0.0.0.0'));
		$this->assertTrue($ip->isIPv6('::ffff:255.255.255.255'));
		$this->assertFalse($ip->isIPv6('::ffff:192.168.256.1'));
		$this->assertFalse($ip->isIPv6('2001:db8::1:192.168.0.1'));

		# Valid check
		$this->assertSame(true, $ip->check('127.0.0.1'));
		$this->assertSame(true, $ip->check('127.0.0.1/32'));
		$this->assertSame(true, $ip->check('::1'));
		$this->assertSame(true, $ip->check('::1/128'));
		$this->assertSame(false, $ip->check('259.0.0.1'));
		$this->assertSame(false, $ip->check('127.0.0.1/117'));
		$this->assertSame(false, $ip->check('9abcd::1'));
		$this->assertSame(false, $ip->check('::1/129'));
	}

	public function testBetween(): void
	{
		$ip = new Ip;

		$this->assertSame(true, $ip->isBetween('127.0.0.1', '127.0.0.0', '127.0.0.255'));
		$this->assertSame(false, $ip->isBetween('::1', '127.0.0.0', '127.0.0.255'));
		$this->assertSame(true, $ip->isBetween('127.0.0.1/16', '127.0.0.0', '127.255.255.255'));

		#
		# IPV4
		#

		# Exact match
		$this->assertSame(true, $ip->isBetween('192.168.0.1', '192.168.0.1', '192.168.0.1'));

		# Inside range
		$this->assertSame(true, $ip->isBetween('192.168.0.50', '192.168.0.1', '192.168.0.100'));

		# Before start
		$this->assertSame(false, $ip->isBetween('192.168.0.0', '192.168.0.1', '192.168.0.100'));

		# After start
		$this->assertSame(false, $ip->isBetween('192.168.0.101', '192.168.0.1', '192.168.0.100'));

		# Edge inclusif
		$this->assertSame(true, $ip->isBetween('10.0.0.1', '10.0.0.1', '10.0.0.255'));
		$this->assertSame(true, $ip->isBetween('10.0.0.255', '10.0.0.1', '10.0.0.255'));

		# Full range
		$this->assertSame(true, $ip->isBetween('8.8.8.8', '0.0.0.0', '255.255.255.255'));

		# Different bytes
		$this->assertSame(true, $ip->isBetween('172.16.5.10', '172.16.0.0', '172.16.255.255'));

		# Out of range
		$this->assertSame(false, $ip->isBetween('172.17.0.1', '172.16.0.0', '72.16.255.255'));

		# Bad padding
		$this->assertSame(false, $ip->isBetween('192.168.001.001', '192.168.0.1', '192.168.0.255'));

		#
		# IPV6
		#

		#  Exact match
		$this->assertSame(true, $ip->isBetween('2001:db8::1', '2001:db8::1', '2001:db8::1'));

		# Inside range
		$this->assertSame(true, $ip->isBetween('2001:db8::5', '2001:db8::1', '2001:db8::10'));

		# Before start
		$this->assertSame(false, $ip->isBetween('2001:db8::0', '2001:db8::1', '2001:db8::10'));

		# After end
		$this->assertSame(false, $ip->isBetween('2001:db8::11', '2001:db8::1', '2001:db8::10'));

		# Loopback (::1) in different notations
		$this->assertSame(true, $ip->isBetween('::1', '::1', '::1'));
		$this->assertSame(true, $ip->isBetween('0:0:0:0:0:0:0:1', '::1', '::1'));

		# Full range (:: to ffff:ffff:....)
		$this->assertSame(true, $ip->isBetween('2001:db8::1', '::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'));

		# Zeros padding
		$this->assertSame(true, $ip->isBetween('2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1', '2001:db8::1'));

		# Edge of subnet
		$this->assertSame(true, $ip->isBetween('2001:db8::ffff', '2001:db8::1', '2001:db8::ffff'));
	}

	public function testIsInRange()
	{
		$ip = new Ip;

		# Simple /24
		$this->assertSame(true, $ip->isInRange('192.168.0.42', ['192.168.0.0/24']));
		$this->assertSame(false, $ip->isInRange('192.168.1.42', ['192.168.0.0/24']));

		# Exact /32 (une seule IP)
		$this->assertSame(true, $ip->isInRange('10.0.0.1', ['10.0.0.1/32']));
		$this->assertSame(false, $ip->isInRange('10.0.0.2', ['10.0.0.1/32']));

		# Large /8
		$this->assertSame(true, $ip->isInRange('10.1.2.3', ['10.0.0.0/8']));
		$this->assertSame(false, $ip->isInRange('11.0.0.1', ['10.0.0.0/8']));

		# Multiple CIDR
		$this->assertSame(true, $ip->isInRange('172.16.5.5', ['192.168.0.0/24', '172.16.0.0/16']));
		$this->assertSame(false, $ip->isInRange('8.8.8.8', ['192.168.0.0/24', '172.16.0.0/16']));

		# Edge of range
		$this->assertSame(true, $ip->isInRange('192.168.0.0', ['192.168.0.0/24']));
		$this->assertSame(true, $ip->isInRange('192.168.0.255', ['192.168.0.0/24']));

		# Full range
		$this->assertSame(true, $ip->isInRange('203.0.113.42', ['0.0.0.0/0']));

		# Not valid CIDR
		$this->assertSame(false, $ip->isInRange('192.168.0.1', ['999.999.999.999/24']));
		$this->assertSame(false, $ip->isInRange('192.168.0.1', ['192.168.0.0/33']));
	}

	public function testCidr2LongIntRange(): void
	{
		$ip = new Ip;

		$this->assertSame([3232235521, 3232235521], $ip->cidr2LongIntRange('192.168.0.1'));

		$this->assertSame([3221225472, 3238002687], $ip->cidr2LongIntRange('192.168.0.1/8'));

		$this->assertSame([3232235520, 3232301055], $ip->cidr2LongIntRange('192.168.0.1/16'));

		$this->assertSame([3232235520, 3232235775], $ip->cidr2LongIntRange('192.168.0.1/24'));
	}

	public function testCidrToRange(): void
	{
		$ip = new Ip;

		$this->assertSame([
			'ip_min_dec' => 3232235521,
			'ip_max_dec' => 3232235521,
			'ip_min' => '192.168.0.1',
			'ip_max' => '192.168.0.1',
			'subnet' => '255.255.255.255',
			'wildcard' => '0.0.0.0',
			'count' => 1,
		], $ip->cidrToRange('192.168.0.1'));

		$this->assertSame([
			'ip_min_dec' => 3232235520,
			'ip_max_dec' => 3232268287,
			'ip_min' => '192.168.0.0',
			'ip_max' => '192.168.127.255',
			'subnet' => '255.255.128.0',
			'wildcard' => '0.0.127.255',
			'count' => 32768,
		], $ip->cidrToRange('192.168.0.1/17'));

		$this->assertSame([
			3232235520 => '192.168.0.0',
			3232235521 => '192.168.0.1',
			3232235522 => '192.168.0.2',
			3232235523 => '192.168.0.3',
		], $ip->cidrToFullRange('192.168.0.1/30'));
	}

	public function testMergeIpRanges(): void
	{
		$ip = new Ip;

		$this->assertSame([
			['192.168.0.0', '192.170.255.255'],
		], $ip->mergeIpRanges([
			['192.168.0.0', '192.168.255.255'],
			['192.169.0.0', '192.169.255.255'],
			['192.170.0.0', '192.170.255.255'],
		]));
	}

	public function testIsIpMatchDomains(): void
	{
		$ip = new Ip;

		$this->assertSame(true, $ip->isIpMatchDomains('127.0.0.1', ['localhost'], true));
		$this->assertSame(false, $ip->isIpMatchDomains('127.0.0.1', ['fake_host']));
	}

	public function testRangeToCIDRIPv6(): void
	{
		$ip = new Ip;

		# Only one
		$this->assertSame(['2001:db8::1/128'], $ip->rangeToCIDRIPv6('2001:db8::1', '2001:db8::1'));

		# Consecutive addresses
		$this->assertSame(['2001:db8::1/128', '2001:db8::2/128'], $ip->rangeToCIDRIPv6('2001:db8::1', '2001:db8::2'));

		# Small block aligned to /127
		$this->assertSame(['2001:db8::/127'], $ip->rangeToCIDRIPv6('2001:db8::', '2001:db8::1'));

		# Full block /64
		$this->assertSame(['2001:db8::/64'], $ip->rangeToCIDRIPv6('2001:db8::', '2001:db8::ffff:ffff:ffff:ffff'));

		# Big range
		$this->assertSame(['2001:db8::/112'], $ip->rangeToCIDRIPv6('2001:db8::', '2001:db8::ffff'));

		# Full range
		$this->assertSame(['::/0'], $ip->rangeToCIDRIPv6('::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'));

		#
		# Another set
		#

		# Block spanning exactly 16 addresses (/124)
		$this->assertSame(['2001:db8::/124'], $ip->rangeToCIDRIPv6('2001:db8::', '2001:db8::f')
		);

		# Block starting non-aligned address
		$this->assertSame(['2001:db8::1/128', '2001:db8::2/127'], $ip->rangeToCIDRIPv6('2001:db8::1', '2001:db8::3'));

		# Full first half of IPv6 (/1)
		$this->assertSame(['::/1','8000::/2'], $ip->rangeToCIDRIPv6('::', 'bfff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'));

		# Very small non-aligned range (/126)
		$this->assertSame(['2001:db8::1/128', '2001:db8::2/127', '2001:db8::4/128'], $ip->rangeToCIDRIPv6('2001:db8::1','2001:db8::4'));

		# Non-contiguous blocks test (simulate several small ranges)
		$this->assertSame(['2001:db8::1/128','2001:db8::3/128'],
			array_merge(
				$ip->rangeToCIDRIPv6('2001:db8::1','2001:db8::1'),
				$ip->rangeToCIDRIPv6('2001:db8::3','2001:db8::3')
			)
		);

		# Check last addresses of IPv6 (/128)
		$this->assertSame(
			['ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127'],
			$ip->rangeToCIDRIPv6('ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
		);
	}

	public function testRangeToCIDRIPv4(): void
	{
		$ip = new Ip;

		# Same IP -> /32
		$this->assertSame(['192.168.1.1/32'], $ip->rangeToCIDRIPv4('192.168.1.1', '192.168.1.1'));

		# Deux IP consécutives -> /31
		$this->assertSame(['192.168.1.0/31'], $ip->rangeToCIDRIPv4('192.168.1.0', '192.168.1.1'));

		# Small unaligned beach -> mix /32 + /31
		$this->assertSame(['192.168.1.1/32', '192.168.1.2/31'], $ip->rangeToCIDRIPv4('192.168.1.1', '192.168.1.3'));
		$this->assertSame(['192.168.1.0/31', '192.168.1.2/32'], $ip->rangeToCIDRIPv4('192.168.1.0', '192.168.1.2'));

		# Perfectly aligned beach on a /30 (4 addresses)
		$this->assertSame(['10.0.0.0/30'], $ip->rangeToCIDRIPv4('10.0.0.0', '10.0.0.3'));

		# Beach not aligned on a block: /32 + /30
		$this->assertSame(['10.0.0.1/32', '10.0.0.2/31'], $ip->rangeToCIDRIPv4('10.0.0.1', '10.0.0.3'));

		# Range on 8 IP aligned -> /29
		$this->assertSame(['172.16.0.0/29'], $ip->rangeToCIDRIPv4('172.16.0.0', '172.16.0.7'));

		# Unaligned beach starting in the middle
		$this->assertSame(['192.168.0.5/32', '192.168.0.6/31', '192.168.0.8/29'], $ip->rangeToCIDRIPv4('192.168.0.5', '192.168.0.15'));

		# Range covering a full 24/7
		$this->assertSame(['172.16.0.0/24'], $ip->rangeToCIDRIPv4('172.16.0.0', '172.16.0.255'));

		# A whole class C (256 IP) -> /24
		$this->assertSame(['192.168.1.0/24'], $ip->rangeToCIDRIPv4('192.168.1.0', '192.168.1.255'));

		# Unaligned range on /24 → block combination
		$this->assertSame(['172.16.0.1/32', '172.16.0.2/31', '172.16.0.4/30', '172.16.0.8/29', '172.16.0.16/28', '172.16.0.32/27', '172.16.0.64/26', '172.16.0.128/25'], $ip->rangeToCIDRIPv4('172.16.0.1', '172.16.0.255'));

		# Full range of 2 addresses at the end of a block
		$this->assertSame(['10.0.0.254/31'], $ip->rangeToCIDRIPv4('10.0.0.254', '10.0.0.255'));

		# Range at the upper limit of the IPv4 space
		$this->assertSame(['255.255.255.254/31'], $ip->rangeToCIDRIPv4('255.255.255.254', '255.255.255.255'));

		# Full range of an entire network (/16)
		$this->assertSame(['192.168.0.0/16'], $ip->rangeToCIDRIPv4('192.168.0.0', '192.168.255.255'));

		# IP range on an atypical border (not a multiple of 2)
		$this->assertSame(['192.0.2.1/32', '192.0.2.2/31'], $ip->rangeToCIDRIPv4('192.0.2.1', '192.0.2.3'));

		# Range over the entire IPv4 space
		$this->assertSame(['0.0.0.0/0'], $ip->rangeToCIDRIPv4('0.0.0.0', '255.255.255.255'));

		# Large beach covering several /24
		$this->assertSame(['10.0.0.0/22'], $ip->rangeToCIDRIPv4('10.0.0.0', '10.0.3.255'));
	}

	public function testCountIPsInCIDR(): void
	{
		$ip = new Ip;

		#
		# IPv4
		#

		$this->assertSame('1', $ip->countIPsInCIDR('192.168.0.1/32'));

		$this->assertSame('2', $ip->countIPsInCIDR('192.168.0.0/31'));

		$this->assertSame('4', $ip->countIPsInCIDR('192.168.0.0/30'));

		$this->assertSame('256', $ip->countIPsInCIDR('10.0.0.0/24'));

		$this->assertSame('65536', $ip->countIPsInCIDR('172.16.0.0/16'));

		$this->assertSame('4294967296', $ip->countIPsInCIDR('0.0.0.0/0'));

		#
		# IPv6
		#

		$this->assertSame('1', $ip->countIPsInCIDR('2001:db8::1/128'));

		$this->assertSame('2', $ip->countIPsInCIDR('2001:db8::/127'));

		$this->assertSame('256', $ip->countIPsInCIDR('2001:db8::/120'));

		$this->assertSame('18446744073709551616', $ip->countIPsInCIDR('2001:db8::/64'));

		$this->assertSame('1208925819614629174706176', $ip->countIPsInCIDR('2001:db8::/48'));

		$this->assertSame('340282366920938463463374607431768211456', $ip->countIPsInCIDR('::/0'));
	}

	public function testExceptionCountIPsInCIDRIPv4(): void
	{
		$ip = new Ip;

		$this->expectException(Exception::class);
		$ip->countIPsInCIDR('0.0.0.0/33');
	}

	public function testExceptionCountIPsInCIDRIPv6(): void
	{
		$ip = new Ip;

		$this->expectException(Exception::class);
		$ip->countIPsInCIDR('::/129');
	}
	public function testCountIPv4sInRange(): void
	{
		$ip = new Ip;

		$this->assertSame(1, $ip->countIPv4sInRange("192.168.0.1", "192.168.0.1"));
		$this->assertSame(2, $ip->countIPv4sInRange("192.168.0.1", "192.168.0.2"));
		$this->assertSame(3, $ip->countIPv4sInRange("192.168.1.1", "192.168.1.3"));
		$this->assertSame(256, $ip->countIPv4sInRange("192.168.0.0", "192.168.0.255"));
		$this->assertSame(65536, $ip->countIPv4sInRange("10.0.0.0", "10.0.255.255"));
		$this->assertSame(4294967296, $ip->countIPv4sInRange("0.0.0.0", "255.255.255.255"));
	}
	public function testCountIPv4sInRangeException(): void
	{
		$ip = new Ip;

		$this->expectException(InvalidArgumentException::class);
		$ip->countIPv4sInRange("999.999.999.999", "192.168.0.1");
	}
	public function testCountIPv4sInRangeExceptionStartingGreaterThanEnding(): void
	{
		$ip = new Ip;

		$this->expectException(InvalidArgumentException::class);
		$ip->countIPv4sInRange("192.168.0.10", "192.168.0.1");
	}
	public function testCountIPv4sInRangeExceptionUnexpected(): void
	{
		$ip = new Ip;

		$this->expectException(InvalidArgumentException::class);
		$ip->countIPv4sInRange("abcd", "efgh");
	}

	public function testCountIPv6sInRange(): void
	{
		$ip = new Ip;

		$this->assertSame('1', $ip->countIPv6sInRange('2001:db8::1', '2001:db8::1'));
		$this->assertSame('2', $ip->countIPv6sInRange('2001:db8::1', '2001:db8::2'));
		$this->assertSame('4', $ip->countIPv6sInRange('2001:db8::', '2001:db8::3'));
		$this->assertSame('5', $ip->countIPv6sInRange('2001:db8::1', '2001:db8::5'));
		$this->assertSame('256', $ip->countIPv6sInRange('2001:db8::', '2001:db8::ff'));
		$this->assertSame('65536', $ip->countIPv6sInRange('2001:db8::', '2001:db8::ffff'));
		$this->assertSame('18446744073709551616', $ip->countIPv6sInRange('2001:db8::', '2001:db8::ffff:ffff:ffff:ffff'));

		# full range 2^128
		$this->assertSame(
			gmp_strval(gmp_add(1, gmp_sub(gmp_pow(2, 128), 1))), // = 2^128
			$ip->countIPv6sInRange('::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
		);

		# crash test
		$this->expectException(InvalidArgumentException::class);
		$ip->countIPv6sInRange('2001:db8::2', '2001:db8::1');
	}

	public function testOptimizeCidrList(): void
	{
		$ip = new Ip;

		$this->assertSame(
			['192.168.0.0/24'],
			$ip->optimizeCidrList(['192.168.0.0/24'])
		);

		$this->assertSame(
			['10.0.0.0/24'],
			$ip->optimizeCidrList(['10.0.0.0/24', '10.0.0.0/24'])
		);

		$this->assertSame(
			['192.168.1.0/24'],
			$ip->optimizeCidrList(['192.168.1.0/25', '192.168.1.128/25'])
		);

		$this->assertSame(
			['172.16.0.0/23'],
			$ip->optimizeCidrList(['172.16.0.0/24', '172.16.1.0/24'])
		);

		$this->assertSame(
			['192.168.1.0/24', '192.168.3.0/24'],
			$ip->optimizeCidrList(['192.168.1.0/24', '192.168.3.0/24'])
		);

		$this->assertSame(
			['10.0.0.0/23', '10.0.2.0/24'],
			$ip->optimizeCidrList([
				'10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24', '10.0.2.0/24'
			])
		);

		$this->assertSame(
			['192.168.4.0/22'],
			$ip->optimizeCidrList([
				'192.168.4.0/24',
				'192.168.5.0/24',
				'192.168.6.0/24',
				'192.168.7.0/24',
			])
		);

		$this->assertSame(
			['10.0.0.0/23'],
			$ip->optimizeCidrList(['10.0.1.0/24', '10.0.0.0/24'])
		);

		$this->assertSame(
			['0.0.0.0/0'],
			$ip->optimizeCidrList([
				'0.0.0.0/1',
				'128.0.0.0/1',
			])
		);
	}

	public function testOrderby()
	{
		$ip = new Ip;

		$this->assertSame([], $ip::orderby([]));

		$this->assertSame([5 => '192.168.0.1'], $ip::orderby([5 => '192.168.0.1']));

		$input = [
			'a' => '192.168.0.1',
			'b' => '10.0.0.2',
			'c' => '10.0.0.1'
		];
		$expectedAsc = [
			'c' => '10.0.0.1',
			'b' => '10.0.0.2',
			'a' => '192.168.0.1'
		];
		$this->assertSame($expectedAsc, $ip::orderby($input, 'asc'));

		$expectedDesc = [
			'a' => '192.168.0.1',
			'b' => '10.0.0.2',
			'c' => '10.0.0.1'
		];
		$this->assertSame($expectedDesc, $ip::orderby($input, 'desc'));

		$input = [
			'x' => '10.0.0.1',
			'y' => '10.0.0.2',
			'z' => '10.0.0.1'
		];
		$expectedAsc = [
			'x' => '10.0.0.1',
			'z' => '10.0.0.1',
			'y' => '10.0.0.2'
		];
		$this->assertSame($expectedAsc, $ip::orderby($input, 'asc'));

		$input = [
			'p' => '10.1.0.1',
			'q' => '192.168.0.1',
			'r' => '10.0.1.1',
			's' => '10.0.0.1'
		];
		$expectedAsc = [
			's' => '10.0.0.1',
			'r' => '10.0.1.1',
			'p' => '10.1.0.1',
			'q' => '192.168.0.1'
		];
		$this->assertSame($expectedAsc, $ip::orderby($input, 'asc'));

		$expectedDesc = [
			'q' => '192.168.0.1',
			'p' => '10.1.0.1',
			'r' => '10.0.1.1',
			's' => '10.0.0.1'
		];
		$this->assertSame($expectedDesc, $ip::orderby($input, 'desc'));
	}

	public function testGetASN(): void
	{
		$ip = new Ip;

		$this->assertSame(15169, $ip->getASN('8.8.8.8'));

		$this->assertSame(15169, $ip->getASN('2001:4860:4860::8888'));

		$this->assertSame(13335, $ip->getASN('1.1.1.1'));
		$this->assertSame(13335, $ip->getASN('2606:4700:4700::1111'));
		$this->assertSame(36692, $ip->getASN('208.67.222.222'));
		$this->assertSame(36692, $ip->getASN('2620:0:ccc::2'));

		# private
		$this->assertSame(0, $ip->getASN('192.168.0.1'));
		$this->assertSame(0, $ip->getASN('10.0.0.1'));
		$this->assertSame(0, $ip->getASN('172.16.0.1'));

		# private
		$this->assertSame(0, $ip->getASN('fc00::1'));
		$this->assertSame(0, $ip->getASN('fe80::1'));

		# bugged
		$this->assertSame(0, $ip->getASN('999.999.999.999'));
		$this->assertSame(0, $ip->getASN('gibberish'));
	}

	public function testGetCidrsFromASN(): void
	{
		$ip = new Ip;

		# ASN Google (15169)
		$googleCidrs = $ip->getCidrsFromASN(15169);
		$this->assertIsArray($googleCidrs);
		$this->assertNotEmpty($googleCidrs);
		$this->assertContains('8.8.8.0/24', $googleCidrs);
		$this->assertContains('2001:4860::/32', $googleCidrs);

		# ASN Cloudflare (13335)
		$cloudflareCidrs = $ip->getCidrsFromASN(13335);
		$this->assertIsArray($cloudflareCidrs);
		$this->assertNotEmpty($cloudflareCidrs);
		$this->assertContains('1.1.1.0/24', $cloudflareCidrs);
		$this->assertContains('2606:4700::/32', $cloudflareCidrs);

		# ASN OpenDNS (36692)
		$openDnsCidrs = $ip->getCidrsFromASN(36692);
		$this->assertIsArray($openDnsCidrs);
		$this->assertNotEmpty($openDnsCidrs);
		$this->assertContains('208.67.222.0/24', $openDnsCidrs);
		$this->assertContains('2620:0:ccc::/48', $openDnsCidrs);

		# Unknown ASN
		$this->assertSame([], $ip->getCidrsFromASN(999999));

		# Private or invalid ASN
		$this->assertSame([], $ip->getCidrsFromASN(0));
		$this->assertSame([], $ip->getCidrsFromASN(-10));

		# Type checking for all elements
		foreach (array_merge($googleCidrs, $cloudflareCidrs, $openDnsCidrs) as $cidr) {
			$this->assertIsString($cidr);
			$this->assertMatchesRegularExpression('/^[0-9a-f:.]+\/\d{1,3}$/i', $cidr);
		}
	}

    public function testParseStr(): void
    {
        $ip = new Ip;

        $list = $ip->parseStrlist('
            # Comment
            13.1.2.3
            13.4.5.6
            13.7.8.9
        ');

        $this->assertSame(['13.1.2.3', '13.4.5.6', '13.7.8.9'], $list);
    }

    public function testWhitelist(): void
    {
        $ip = new Ip;

        $whitelist = ['13.1.2.3', '13.4.5.6', '13.7.8.9'];
        $list = $ip->splitRange('13.0.0.0', '13.255.255.255', $whitelist);

        $this->assertSame([
            ['start' => '13.0.0.0', 'end' => '13.1.2.2'],
            ['start' => '13.1.2.4', 'end' => '13.4.5.5'],
            ['start' => '13.4.5.7', 'end' => '13.7.8.8'],
            ['start' => '13.7.8.10', 'end' => '13.255.255.255'],
        ], $list);
    }
}