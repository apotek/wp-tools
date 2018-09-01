#!/usr/bin/env php
<?php
/**
 * Call this script with `--debug` flag if you need to see the calls that are
 * being made to the vulnerability database.
 */

class wpvulndb_report {
  const COLUMN_WIDTH = 14;
  const COLUMN_WIDTH_FIRST = 36;
  protected static $TYPE_OUTOFDATE = 'OD';
  protected static $TYPE_UNKNOWN = 'U';
  protected static $TYPE_VULNERABLE = 'V';
  protected static $_items = array();
  protected static $_outofdate = 0;
  protected static $_report = array();
  protected static $_unknown = 0;
  protected static $_vulnerable = 0;

  private static function _column($string, $pad = wpvulndb_report::COLUMN_WIDTH, $dir = STR_PAD_LEFT) {
    // Chop data to fit to the column.
    $string = substr($string, 0, $pad -1);
    return str_pad($string, $pad, ' ', $dir);
  }
  private static function _row(array $items, &$line = '') {
    $row = array();
    $row[] = static::_column(array_shift($items), wpvulndb_report::COLUMN_WIDTH_FIRST, STR_PAD_RIGHT);
    foreach ($items as $item) {
      $row[] = static::_column($item);
    }
    if ($line) {
      $line_width = wpvulndb_report::COLUMN_WIDTH_FIRST + (count($items) * wpvulndb_report::COLUMN_WIDTH);
      $line = str_pad($line, $line_width, $line);
    }

    return $row;
  }

  public static function mark($key, $marker) {
    if (empty(static::$_items[$key][$marker])) {
      if (empty(static::$_items[$key])) {
        static::$_items[$key] = array();
      }
      static::$_items[$key][$marker] = 1;
    }
    else {
      static::$_items[$key][$marker]++;
    }
  }

  public static function mark_outofdate(wpvulndb_response $wr) {
    static::mark((string)$wr, static::$TYPE_OUTOFDATE);
    static::$_outofdate++;
  }

  public static function mark_unknown(wpvulndb_response $wr) {
    static::mark((string)$wr, static::$TYPE_UNKNOWN);
    static::$_unknown++;
  }

  public static function mark_vulnerable($wr) {
    static::mark((string)$wr, static::$TYPE_VULNERABLE);
    static::$_vulnerable++;
  }

  public static function print_report($full = FALSE) {
    if (static::$_items) {
      $header = array('Name', 'Unknown', 'Out of Date', 'Vulnerabilities');
      $line = '=';
      echo implode('', static::_row($header, $line)) . "\n";
      echo $line . "\n";
    }
    foreach (static::$_items as $name => $item) {
      echo implode('', static::_row(array($name, (!empty($item[static::$TYPE_UNKNOWN]) ? $item[static::$TYPE_UNKNOWN] : '.'), (!empty($item[static::$TYPE_OUTOFDATE]) ? $item[static::$TYPE_OUTOFDATE] : '.'), (!empty($item[static::$TYPE_VULNERABLE]) ? $item[static::$TYPE_VULNERABLE] : '.')))) . "\n";
    }
    if (static::$_items) {
      $totals = array('Total', static::$_unknown, static::$_outofdate, static::$_vulnerable);
      $line = '-';
      $row = static::_row($totals, $line);
      echo $line . "\n";
      echo implode('', $row) . "\n";
    }
    if (static::$_vulnerable) {
      echo "\n\nVulnerabily Report:\n";
      echo "Item\tType\tTitle\tUrl\tFixed in\n";
      foreach (static::$_report as $item => $vulns_per_item) {
        foreach ($vulns_per_item as $vuln) {
          echo $item . "\t" . $vuln->vuln_type . "\t" . $vuln->title . "\t" . $vuln->references->url[0] . "\t" . $vuln->fixed_in . "\n";
        }
      }
    }
  }

  public static function add_vulnerability(wpvulndb_response $wr, $vulnerability) {
    static::mark_vulnerable($wr);
    $key = (string)$wr;
    if (empty(static::$_report[$key])) {
      static::$_report[$key] = array();
    }
    static::$_report[$key][$vulnerability->id] = $vulnerability;
  }

  public static function vulnerable() {
    return static::$_vulnerable;
  }
}

class wpvulndb_response {
  protected $_error;
  protected $_id;
  protected $_item;
  protected $_version;

  public function __construct($item, $version) {
    $this->_item = $item;
    $this->_version = $version;
  }

  public function __toString() {
    return $this->_item . '@' . $this->_version;
  }

  public function report() {
    $feedback = '';
    if ($this->_error) {
      $feedback = "Error: {$this->_error}";
      wpvulndb_report::mark_unknown($this);
    }
    else {
      $search = FALSE;
      if (property_exists($this, 'status')) {
        $feedback = " Status: {$this->status}";
        if ($this->status == 'insecure') {
          wpvulndb_report::mark_vulnerable($this);
          $search = TRUE;
        }
        else if ($this->status == 'Not found') {
          wpvulndb_report::mark_unknown($this);
        }
      }
      if (property_exists($this, 'latest_version')) {
        if (version_compare($this->_version, $this->latest_version, '<')) {
          wpvulndb_report::mark_outofdate($this);
          $search = TRUE;
        }
      }
      if (property_exists($this, 'vulnerabilities') && is_array($this->vulnerabilities)) {
        $vcount = count($this->vulnerabilities);
      }
      else {
        $vcount = 0;
      }
      if ($search && $vcount) {
        $unpatched = 0;
        foreach ($this->vulnerabilities as $ix => $vuln) {
          if (version_compare($this->_version, $vuln->fixed_in, '<')) {
            $unpatched++;
            wpvulndb_report::add_vulnerability($this, $vuln);
          }
        }
      }
    }
    if ($feedback) {
      echo "{$this->_item} @ {$this->_version}: $feedback\n";
    }
    return $this;
  }

  public function load(stdClass $data) {
    foreach ($data as $property => $value) {
      $this->{$property} = $value;
    }
    return $this;
  }

  public function set_error($err) {
    $this->_error = $err;
    return $this;
  }

  public function set_status($status) {
    $this->status = $status;
    return $this;
  }
}

class wpvulndb {
  private static $_api_base = 'https://wpvulndb.com/api/v3/';
  private static $_client;
  public static $debug = FALSE;
  protected static $_ini_file = '.wpvulndb.ini';
  // Token is set in the following order of priority: command line
  // option -t, command line option --token, environement variable
  // WPVULNDB_TOKEN, setting wpvulndb_token in ./.wpvulndb.ini,
  // setting wpvulndb_token in ~/.wpvulndb.ini file.
  protected static $_token;

  public static function request($type, $item, $version = '') {
    global $argc;
    if (is_null(static::$_client)) {
      // Let's look at the command line options.
      $options = getopt('t:d', array('debug', 'token:'));
      if (isset($options['d']) || isset($options['debug'])) {
        static::$debug = TRUE;
      }
      if (isset($options['t'])) {
        static::$_token = $options['t'];
      }
      else if (isset($options['token'])) {
        static::$_token = $options['token'];
      }
      if (is_null(static::$_token)) {
        if ($token = getenv('WPVULNDB_TOKEN')) {
          static::$_token = $token;
        }
        $settings_files = array(
          './' . static::$_ini_file,
          getenv('HOME') . '/' . static::$_ini_file,
        );
        foreach ($settings_files as $file) {
          if (file_exists($file) && is_readable($file)) {
            if (static::$debug) {
              echo "Reading settings from $file\n";
            }
            $settings = parse_ini_file($file);
            if (isset($settings) && is_array($settings) && isset($settings['token'])) {
              static::$_token = $settings['token'];
            }
          }
        }
        if (empty(static::$_token)) {
          echo "No api token could be found for access to the wpvulndb.\n";
          echo "Please either pass it on the command line with -t or --token\n";
          echo "or set environment variable WPVULNDB_TOKEN, or set it in either\n";
          echo implode(', or ', $settings_files) . "\n";
          exit(1);
        }
      }
      static::$_client = curl_init();
      curl_setopt(static::$_client, CURLOPT_FOLLOWLOCATION, TRUE);
      curl_setopt(static::$_client, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt(static::$_client, CURLOPT_HTTPHEADER, array('Authorization: Token token=' . static::$_token));

      register_shutdown_function(array('wpvulndb', 'destruct'));
    }
    curl_setopt(static::$_client, CURLOPT_VERBOSE, static::$debug);

    $type = trim($type);
    $item = trim($item);
    $version = trim($version);
    switch ($type) {
      case 'core':
      case 'wordpress':
      case 'wordpresses':
        $api_id = str_replace('.', '', $item);
        $api_path = 'wordpresses';
        $wr = new wpvulndb_response('wordpress', $item);
        break;
      default:
        $api_id = $item;
        $api_path = $type;
        $wr = new wpvulndb_response($item, $version);
        break;
    }

    $url = static::$_api_base . $api_path . '/' . $api_id;
    curl_setopt(static::$_client, CURLOPT_URL, $url);

    $response = curl_exec(static::$_client);
    if ($response === FALSE) {
      $wr->set_error(curl_error(static::$_client));
    }
    else {
      $data = json_decode($response);
      if (!is_object($data)) {
        $wr->set_error($response);
      }
      else {
        if (property_exists($data, $item)) {
      	  $wr->load($data->{$item});
        }
        else if (isset($data->error)) {
          // Usually indicates either unauthorized or not found.
          $wr->set_status($data->error);
        }
        else {
          // Catch all. I have not seen a use-case for this. We got
          // an object, but we don't know what it is, so return just
          // the raw response.
          $wr->set_error($response);
        }
      }
    }
    return $wr;
  }

  public static function destruct() {
    curl_close(static::$_client);
  }
}


$wpv = shell_exec('./wp-cli.phar core version');
#wpvulndb::$debug = TRUE;// Or just pass --debug to the command line.
$resp = wpvulndb::request('core', $wpv);
$resp->report();

$plugins = array();
exec('./wp-cli.phar plugin list | grep "active" | cut -f 1,4', $plugins);

foreach ($plugins as $row) {
  $matches = array();
  $row = trim($row);
  preg_match('/^([^\s]+)\s+([^\s]+)$/', $row, $matches);
  $resp = wpvulndb::request('plugins', $matches[1], $matches[2]);
  $resp->report();
}

wpvulndb_report::print_report();

exit(wpvulndb_report::vulnerable());
