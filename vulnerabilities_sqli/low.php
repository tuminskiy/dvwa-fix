<?php

if (isset($_REQUEST['Submit'])) {
  // Get input
  $id = $_REQUEST['id'];
  if ($id > 2 and $id <5) {
    $html .= "<p>Sorry, you are not authorized to see that user's information</p>";
  }
  else {
    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query);

    if (!$result) {
      $text = "";

      if (is_object($GLOBALS["___mysqli_ston"])) {
        $text = mysqli_error($GLOBALS["___mysqli_ston"])
      }
      else {
        $text = ($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false;
      }

      die('<pre>'.$text.'</pre>');
    }

    // Get results
    while ($row = mysqli_fetch_assoc($result)) {
    // Get values
      $first = $row["first_name"];
      $last  = $row["last_name"];

      // Feedback for end user
      $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }
  }

  mysqli_close($GLOBALS["___mysqli_ston"]);
}

?>