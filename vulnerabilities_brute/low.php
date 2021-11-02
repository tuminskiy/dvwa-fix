<?php
// CWE-20, CWE-598
if (isset($_POST[ 'Login' ]) && isset($_POST[ 'username' ]) && isset($_POST[ 'password' ])) {
	$ston = $GLOBALS["___mysqli_ston"];

	// CWE-89
	$user = mysqli_real_escape_string($ston, $_POST[ 'username' ]);
	$pass = mysqli_real_escape_string($ston, $_POST[ 'password' ]);	
	$pass = md5( $pass );

	$max_failed_login = 3;
	$ban_time = 15;
	$is_banned = false;

	// CWE-307	
	$stmt = $ston->prepare("SELECT failed_login, last_login FROM users WHERE user = ? LIMIT 1;");
	$stmt->bind_param("s", $user);
	$stmt->execute();
	$stmt->store_result();
	$stmt->bind_result($failed_login, $last_login);
	$stmt->fetch();
	$timeout = 0;

	if ($stmt->num_rows == 1 && $failed_login  >= $max_failed_login) {
		// Caclculate when the user would be allowed to login again
		$last_login = strtotime($last_login);
		$timeout = $last_login + $ban_time * 60;
		$timenow = time();
		$is_banned = $timenow < $timeout;
	}


	if (!$is_banned) {
		// CWE-89
		$stmt = mysqli_prepare($ston, "SELECT avatar FROM users WHERE user = ? AND password = ? LIMIT 1;");
		$stmt->bind_param("ss", $user, $pass);
		$stmt->execute();
		$stmt->store_result();
		$stmt->bind_result($avatar);
		$stmt->fetch();

		if ($stmt->num_rows == 1) {
			// Login successful
			$html .= "<p>Welcome to the password protected area {$user}</p>";
			$html .= "<img src=\"{$avatar}\" />";
			
			$stmt = mysqli_prepare($ston, "UPDATE users SET failed_login = \"0\" WHERE user = ? LIMIT 1;");
			$stmt->bind_param("s", $user);
			$stmt->execute();
		} else {
			// Login failed
			$html .= "<pre><br />Username and/or password incorrect.</pre>";

			$stmt = mysqli_prepare($ston, "UPDATE users SET failed_login = (failed_login + 1) WHERE user = ? LIMIT 1;");
			$stmt->bind_param("s", $user);
			$stmt->execute();
		}		
	} else {
		$dt = date_create();
		date_timestamp_set($dt, $timeout);
		$html .= "<pre><br/>You were banned until ".date_format($dt, "Y-m-d H:i:s")."</pre>";
	}
			
	$stmt = mysqli_prepare($ston, "UPDATE users SET last_login = now() WHERE user = ? LIMIT 1;");
	$stmt->bind_param("s", $user);
	$stmt->execute();
	
	((is_null($___mysqli_res = mysqli_close($ston))) ? false : $___mysqli_res);
}

?>
