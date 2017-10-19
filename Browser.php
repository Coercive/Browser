<?php
namespace Coercive\Utility\Browser;

use Mobile_Detect;

/**
 * Class Browser
 *
 * @package		Coercive\Utility\Browser
 * @link		@link https://github.com/Coercive/browser
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   (c) 2017 - 2018 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Browser {

	/** @var string SERVER */
	private $_REMOTE_ADDR = null;
	private $_HTTP_X_FORWARDED_FOR = null;

	/** @var  array|string User Agent */
	private $sUserAgent;

	/**
	 * Mobile detect
	 *
	 * @source www.detectmobilebrowsers.com
	 * @var string $sDetectMobile (for pregmatch)
	 */
	private $sDetectMobile = '/(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows (ce|phone)|xda|xiino/i';

	/**
	 * Mobile detect
	 *
	 * @source www.detectmobilebrowsers.com
	 * @var string $sDetectMobile (for pregmatch)
	 */
	private $sDetectMobile_abr = '/1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i';

	/**
	 * Récupération des données renvoyées par le client.
	 */
	public function __construct() {

		# User Agent from server
		$this->sUserAgent = filter_input(INPUT_SERVER, 'HTTP_USER_AGENT', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

		# IP + Port from server
		$this->_REMOTE_ADDR = filter_input(INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
		$this->_HTTP_X_FORWARDED_FOR = filter_input(INPUT_SERVER, 'HTTP_X_FORWARDED_FOR', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

	}

	/**
	 * ALIAS MOBILE_DETECT
	 *
	 * @return Mobile_Detect
	 */
	public function Mobile_Detect() {
		static $_oMobile = null;
		if(!$_oMobile) { $_oMobile = new Mobile_Detect; }
		return $_oMobile;
	}

	/**
	 * GET IP
	 *
	 * @return string
	 */
	public function getIP() {

		# IP potentielle
		$sIp = $this->_HTTP_X_FORWARDED_FOR ? $this->_HTTP_X_FORWARDED_FOR : $this->_REMOTE_ADDR;
		$sIp = str_replace(' ', '', $sIp);

		// NOT STRPOS => strrpos
		$iPos = strrpos($sIp, ',') ? strrpos($sIp, ',') + 1 : false;
		if($iPos !== false) { $sIp = substr($sIp, $iPos); }

		# IP Réelle (ou la plus profonde fournie par le routeur)
		return $sIp;
	}

	/**
	 * Vérifie une adresse IP dans une plage donnée
	 *
	 * @param string $sRange - IP/CIDR netmask : 127.0.0.0/24, aussi 127.0.0.1 est accepté et /32 présumé
	 * @param string $sIp - IPV4 format : 127.0.0.1
	 * @return bool
	 */
	public function isClientIpInRange($sRange, $sIp=null) {

		# O ou false : Ajouter le netmask /32 présumé
		if (strpos($sRange, '/') == false) { $sRange .= '/32'; }

		# Séparer range du netmask pour traitement
		list($sRange, $sNetmask) = explode('/', $sRange, 2);
		$iRange = ip2long($sRange);

		# Ip reçu ou Ip courante
		$iIp = $sIp ? ip2long($sIp) : ip2long($this->getIP());

		# 2 puissante (différence netmaks) moins 1 : php5.6 utiliser ** opérateur
		$fWildcard = pow(2, (32 - $sNetmask)) - 1;

		# Gestion float
		$iNetmask = ~ $fWildcard;

		# Dans le range : true
		return ($iIp & $iNetmask) === ($iRange & $iNetmask);
	}

	/**
	 * GET AGENT
	 *
	 * @return string
	 */
	public function getAGENT() {
		return $this->sUserAgent;
	}

	/**
	 * Détection d'un navigateur de téléphone mobile.
	 * Source : www.detectmobilebrowsers.com
	 *
	 * @return bool
	 */
	public function mobile() {
		return preg_match($this->sDetectMobile, $this->sUserAgent) || preg_match($this->sDetectMobile_abr, substr($this->sUserAgent, 0, 4));
	}

	/**
	 * Détection de la plateforme.
	 *
	 * @return string
	 */
	public function os() {
		$sPlatform = 'Unknown';

		if (preg_match('/linux/i', $this->sUserAgent)) {
			$sPlatform = 'Linux';
		} elseif (preg_match('/macintosh|mac os x/i', $this->sUserAgent)) {
			$sPlatform = 'Mac';
		} elseif (preg_match('/windows|win32/i', $this->sUserAgent)) {
			$sPlatform = 'Windows';
		}

		return $sPlatform;
	}

	/**
	 * Détection du navigateur.
	 *
	 * @return array
	 */
	public function browser() {
		$sBrowserName = 'Unknown';
		$sNameForSearchVersion = 'Unknown';

		// Nom du navigateur
		if (preg_match('/MSIE/i', $this->sUserAgent) && !preg_match('/Opera/i', $this->sUserAgent)) {
			$sBrowserName = 'Internet Explorer';
			$sNameForSearchVersion = 'MSIE';
		} elseif (preg_match('/Firefox/i', $this->sUserAgent)) {
			$sBrowserName = 'Mozilla Firefox';
			$sNameForSearchVersion = 'Firefox';
		} elseif (preg_match('/Chrome/i', $this->sUserAgent)) {
			$sBrowserName = 'Google Chrome';
			$sNameForSearchVersion = 'Chrome';
		} elseif (preg_match('/Safari/i', $this->sUserAgent)) {
			$sBrowserName = 'Apple Safari';
			$sNameForSearchVersion = "Safari";
		} elseif (preg_match('/Opera/i', $this->sUserAgent)) {
			$sBrowserName = 'Opera';
			$sNameForSearchVersion = 'Opera';
		} elseif (preg_match('/Netscape/i', $this->sUserAgent)) {
			$sBrowserName = 'Netscape';
			$sNameForSearchVersion = 'Netscape';
		}

		// Version du navigateur.
		$aKnown = ['Version', $sNameForSearchVersion, 'other'];
		$sPattern = '#(?<browser>' . join('|', $aKnown) . ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
		if (!preg_match_all($sPattern, $this->sUserAgent, $aMatches)) {
			// Si aucun numéro n'est trouvé, on continue
		}

		// Combien de numéro de version son trouvé ?
		$i = isset($aMatches['browser']) ? count($aMatches['browser']) : 1;
		if ($i != 1) {
			// On en a deux, on n'utilise pas 'other'
			// Vérifier si la version est avant ou après le nom
			if (strripos($this->sUserAgent, 'Version') < strripos($this->sUserAgent, $sNameForSearchVersion)) {
				$mVersion = isset($aMatches['version'][0]) ? $aMatches['version'][0] : 'Unknow';
			} else {
				$mVersion = isset($aMatches['version'][1]) ? $aMatches['version'][1] : 'Unknow';
			}
		} else {
			$mVersion = isset($aMatches['version'][0]) ? $aMatches['version'][0] : 'Unknow';
		}

		// Vérification de la présence d'un numéro de version
		if ($mVersion == null || $mVersion == '') {
			$mVersion = '?';
		}

		return [
			'name'    => $sBrowserName,
			'version' => $mVersion
		];
	}
}