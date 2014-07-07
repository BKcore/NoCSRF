<?php
session_start();

include('../nocsrf.php');

if ( isset( $_POST[ 'field' ] ) )
{
	try
	{
		// Run CSRF check, on POST data, in exception mode, for 10 minutes, in one-time mode.
		NoCSRF::check( 'csrf_token', $_POST, true, 60*10, false );
		// form parsing, DB inserts, etc.
		// ...
		$result = 'CSRF check passed. Form parsed.';
	}
	catch ( Exception $e )
	{
		// CSRF attack detected
		$result = $e->getMessage() . ' Form ignored.';
	}
}
else
{
	$result = 'No post data yet.';
}
// Generate CSRF token to use in form hidden field
$token = NoCSRF::generate( 'csrf_token' );
?>


<h1>CSRF sandbox</h1>
<pre style="color: red"><?php echo $result; ?></pre>
<form name="csrf_form" action="#" method="post">
	<h2>Form using generated token.</h2>
	<input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
	<input type="text" name="field" value="somevalue">
	<input type="submit" value="Send form">
</form>
<form name="nocsrf_form" action="#" method="post">
	<h2>Copied form simulating CSRF attack.</h2>
	<input type="hidden" name="csrf_token" value="whateverkey">
	<input type="text" name="field" value="somevalue">
	<input type="submit" value="Send form">
</form>
