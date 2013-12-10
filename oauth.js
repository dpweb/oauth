var debug = process.env.debugoauth,
    request = require('request');
    qs = require('querystring');

function sortKeys(h){
    var h2 = {}; Object.keys(h).sort().forEach(function(k) {h2[k]=h[k]});
    return h2;
}

function OAuth1(config){
	var Hashes = require('jshashes'), 
        eu = encodeURIComponent, 
        util = require('util');
	return {
        calcHeaders: function(method, url, data, more){
            var p = [], hdrstr = [];
            var h = {
                oauth_consumer_key: config.oauth_consumer_key,
                oauth_nonce: Math.random().toString(36).substring(2, 15),
                oauth_signature_method: "HMAC-SHA1",
                oauth_timestamp: Math.floor(new Date()/1000),
                oauth_version: '1.0'
            }, p = [];
            // for webflow or override
            for(i in more) h[i] = eu(more[i]);

            if(!more && config.oauth_token) h.oauth_token = config.oauth_token;
            h = sortKeys(h);
            for(i in h) p.push(eu(i + '=' + h[i])); 

            var sigbase = method + '&' + eu(url) + '&' + p.join(eu('&')) + (data ? eu('&' + data):'');
            var sigkey = config.consumer_secret + '&' + config.token_secret;
            if(debug) console.log('\n\nSIGBASE', sigbase, '\n\nSIGKEY', sigkey);

            h.oauth_signature = eu(new Hashes.SHA1().b64_hmac(sigkey, sigbase));
            h = sortKeys(h);
            for(i in h) hdrstr.push(util.format('%s="%s"', i, h[i]));
            var auth_header =  'OAuth ' + hdrstr.join(', ');
            if(debug) console.log('\nCALCD HEADERS', auth_header);
            return auth_header;
        },
		api: function(method, url, data, cb){
            var auth_header = this.calcHeaders(method, url, data);
            if(debug) console.log('HEADERS', auth_header);
            request({url: url + '?' + data, headers: {"Authorization": auth_header}}, function(e, r, b){
                if(e) throw e;
                cb(JSON.parse(b));
            });
		},
        asCurl: function(method, url, data){
            var h = this.calcHeaders(method, url, data);
            return util.format("curl --get '%s' --data '%s' --header '%s' --verbose", url, data, h);
        }
	}
}

// OAuth 2.0 Client Credentials Grant - aka Twitter Application-Only Auth
//   http://tools.ietf.org/html/rfc6749#section-4.4
//   https://dev.twitter.com/docs/auth/application-only-auth

function OAuth2(config){
    var r = require('request');
    return {
        tok: null,
        api: function(name, cb){
            var th = this;
            if(!this.tok){
                r.post({url: config.oauth2_token_url,
                    headers: {Authorization: 'Basic ' + new Buffer(config.oauth_consumer_key +':'+ config.consumer_secret).toString('base64')},
                    form: {grant_type: 'client_credentials'}
                }, function(e,r,b){
                    if(debug) console.log(b); 
                    th.tok=JSON.parse(b).access_token; th.api(name, cb)});
                return;
            }
            r.get({
                url: name,
                headers: {Authorization: 'Bearer ' + th.tok}
            }, function(e,r,b){cb(JSON.parse(b))})
        }
    }
}

strats = {
    "github": {
        authenticate: function(r, s, n){
                if(r.body.hasOwnProperty('access_token')){
                    console.log(r.body.access_token)
                    return n();
                }
                if(!r.body.hasOwnProperty('code')){
                    request('https://github.com/login/oauth/authorize?client_id=de1f8321ad576de8583e', function(e, r, b){
                        console.log(r, b);  // that.info.access_token =''
                    });
                    return n();
                }
                var ra = this.config;
                ra.code = r.body.code;
                console.log(ra);

                var that = this;
                request.post('https://github.com/login/oauth/access_token', ra, function(e, r, b){
                    console.log(b);  // that.info.access_token =''
                });
                n();
        },
        api: function(r, s, n){

        }
    }
}

function webflow(config, app){
    for(name in strats){
        strats[name].config = config[name];
        app.get(/./, function(r, s, n){
            strats[name].authenticate.call(strats[name], r, s, n);
        })
    }
    /*var auth_header = OAuth1(config).calcHeaders('POST', 'https://api.twitter.com/oauth/request_token', null, 
        { 
            oauth_callback: "http://mymapp.com/",
        });
    request.post({url: "https://api.twitter.com/oauth/request_token", headers: {"Authorization": auth_header}}, function(e, r, b){
        if(e) throw e;
        console.log(b);
    });  
    */
}


module.exports = {
    v1: OAuth1,
    v2: OAuth2,
    webflow: webflow
}