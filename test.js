var OAuth = require('./oauth.js'),
	config = require('./config.json');
	require('colors');

var oa1 = OAuth.v1(config.twitter);
oa1.api('GET', 'https://api.twitter.com/1.1/search/tweets.json', 'q=javascript', function(o){
	console.log(o.statuses[0].text.blue);
	if(o.statuses) console.log('OA1.api() OK'.green);
	var curlstr = oa1.asCurl('GET', 'https://api.twitter.com/1.1/search/tweets.json', 'q=javascript');
	console.log(curlstr);
	console.log('OA1.asCurl() OK'.green);

	var oa2 = OAuth.v2(config.twitter);
	oa2.api('https://api.twitter.com/1.1/lists/statuses.json?slug=testlist&owner_screen_name=@digplan', function(o){
		console.log(o[0].text.blue);
		console.log('OA2.api() OK'.green);
	});

});
