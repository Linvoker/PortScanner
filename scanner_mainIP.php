<?php
//echo "hello, world\n";
class Scanner {
	public function __construct() {
        //ip放在json文件里
        $valid_IP_array = $this->readJsonDataFromFile("total_evil_ip_level.map");
		if	(empty($valid_IP_array) === true) {
			echo "failed to change this file to an array\n";
			exit;
		}
		ksort($valid_IP_array);
		$this->pointer_of_record_file = fopen('IP_list', 'w');
		foreach($valid_IP_array as $key => $value) {
			if(filter_var($key, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
				fwrite($this->pointer_of_record_file, "$key\n");
			//	$count_array = $value;
				$this->record_IP_addr($key);
				if ($this->scan() === true) {
					foreach($value as $key => $value) {
						fwrite($this->pointer_of_record_file, "\t$key $value\n");
					}
					fwrite($this->pointer_of_record_file, "\n");
				}
			}
		}
		fclose($this->pointer_of_record_file);
	}

	private function readJsonDataFromFile($file) {
		if (! file_exists ( $file )) {
			return array ();
		}
		$contents = file_get_contents ( $file );
		if ($contents == "null") {
			return array ();
		}
		$dataObj = json_decode ( $contents, true );
		return $dataObj;
	}

	private function record_IP_addr($candidate) {
		$this->curr_IP_addr = trim( $candidate );
	}
	private function scan() {
        //要扫描的端口号
		$port_array = array(21, 22, 23);
		$start_index = 0;
		$end_index = count($port_array) - 1;
		$is_server = false;
		for( $i = $start_index; $i <= $end_index; $i++ ) {
			$scan_socket = socket_create( AF_INET, SOCK_STREAM, SOL_TCP );

			$MAX_CONNECT_TIME_SEC = 0;
            $MAX_CONNECT_TIME_USEC = 300000;
            //设置socket_connect三次握手的发送和接受的时限
			socket_set_option($scan_socket, SOL_SOCKET, SO_RCVTIMEO,
					array('sec' => $MAX_CONNECT_TIME_SEC, 'usec' => $MAX_CONNECT_TIME_USEC));
			socket_set_option($scan_socket, SOL_SOCKET, SO_SNDTIMEO,
					array('sec' => $MAX_CONNECT_TIME_SEC, 'usec' => $MAX_CONNECT_TIME_USEC));

			$connected = @socket_connect($scan_socket, $this->curr_IP_addr, $port_array[$i]);

			if( $connected == true ) {
				//print "\r\t [ port - ".$port_array[$i]."\t\topen ]\n";
				fwrite($this->pointer_of_record_file,
						"\t[ port - ".$port_array[$i]."\topen ]\n");
				$is_server = true;
			}

			socket_close( $scan_socket );
		}
		return $is_server;

	}

	private $pointer_of_record_file;
	private $curr_IP_addr;
}

	$instance = new Scanner();
?>
