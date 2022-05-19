'use strict';

const { exception } = require('console');
const { CreateConsentDataPermissionsEnum, ConsentsApi, AccountsApi } = require('./api_accounts_open_banking_brasil');

const USE_PAR = true;
const USE_DYNAMIC_SCOPE = true;

(async () => {
    const { Issuer, custom, generators /*, TokenSet */ } = require('openid-client');
    const fs = require('fs');
    // const jose = require('jose');
    const crypto = require('crypto');
    const pki = require('node-forge').pki;
    const express = require('express');
    const cookieParser = require('cookie-parser');
    const app = express();
    const path = require('path');
    const https = require('https');
    const { default: axios } = require('axios');
    const jp = require('jsonpath');
    const { default: fromKeyLike } = require('jose/jwk/from_key_like');


    const certsPath = path.join(__dirname, './certs/');

    const key = crypto.createPrivateKey(fs.readFileSync(certsPath + 'signing.key'));
    const privateJwk = await fromKeyLike(key);
    // const privateJwk = await jose.exportJWK(key);
    privateJwk.kid = '8o-O3VSFOPE8TrULXUTHxhxJcdADKIBmsfE0KWYkHik';

    // const ks = fs.readFileSync(certsPath + "signing.jwk");
    // var privateJwk = await jose.createLocalJWKSet(JSON.parse(ks.toString()));

    console.log('Create private jwk key %O', privateJwk);

    const keyset = {
        keys: [
            privateJwk
        ]
    };

    const httpsAgent = new https.Agent({
        ca: fs.readFileSync(certsPath + 'ca.pem'),
        key: fs.readFileSync(certsPath + 'transport.key'),
        cert: fs.readFileSync(certsPath + 'transport.pem'),
        rejectUnauthorized: false,
    });

    const instance = axios.create({ httpsAgent });

    const directoryResponse = await instance.get('https://auth.sandbox.directory.openbankingbrasil.org.br/.well-known/openid-configuration');

    const directoryConfiguration = directoryResponse.data;
    // console.log(directoryConfiguration);

    const params = new URLSearchParams()
    params.append('grant_type', 'client_credentials')
    params.append('scope', 'directory:software')
    params.append('client_id', 'QjRzruzFWi_U_tMahlz01')

    const directoryToken = await instance.post(directoryConfiguration.mtls_endpoint_aliases.token_endpoint, params, {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });
    // console.log(`Bearer ${directoryToken.data.access_token}`);
    // 74e929d9-33b6-4d85-8ba7-c146c867a817
    // 10120340-3318-4baf-99e2-0b56729c4ab2
    const softwareAssertion = await instance.get('https://matls-api.sandbox.directory.openbankingbrasil.org.br/organisations/74e929d9-33b6-4d85-8ba7-c146c867a817/softwarestatements/10120340-3318-4baf-99e2-0b56729c4ab2/assertion',
        {
            headers: {
                "Accept": "application/jwt;charset=UTF-8",
                'Authorization': `Bearer ${directoryToken.data.access_token}`
            }
        });
    // console.log('Software Assertion ' + softwareAssertion.data);

    const ca = softwareAssertion.data;
    const base64Url = ca.split('.')[1];
    const decodedValue = JSON.parse(Buffer.from(base64Url, 'base64'));
    console.log('Software Assertion JWKS URL ' + decodedValue.software_jwks_uri);

    const certBuf = fs.readFileSync(certsPath + 'transport.pem');


    const cert = pki.certificateFromPem(certBuf.toString());
    const subject = cert.subject.attributes
        .map(attr => [attr.shortName, attr.value].join('='))
        .join(', ');

    console.log(subject); // "C=US, ST=Cal

    const dcrRequest = {
        grant_types: [
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials"
        ],
        tls_client_auth_subject_dn: subject,
        jwks_uri: decodedValue.software_jwks_uri,
        token_endpoint_auth_method: "tls_client_auth",
        response_types: [
            "code id_token"
        ],
        redirect_uris: [
            "https://localhost.emobix.co.uk:8443/test/a/obbsb/callback"
        ],
        software_statement: softwareAssertion.data
    };

    const dcrRegistration = await instance.post('https://matls-auth.mockbank.poc.raidiam.io/reg', dcrRequest, {
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-Charset': 'utf-8',
        }
    });
    console.log(`DCR ClientID ${dcrRegistration.data.client_id}`);
    console.log(`DCR registration_client_uri ${dcrRegistration.data.registration_client_uri}`);
    console.log(`DCR registration_access_token ${dcrRegistration.data.registration_access_token}`);
    console.log(JSON.stringify(dcrRegistration.data));





    const axiosResponse = await instance.get('https://data.sandbox.directory.openbankingbrasil.org.br/participants');
    const availableBanks = axiosResponse.data;
    // console.log(JSON.stringify(availableBanks));
    let authServer;
    const foundBank = availableBanks.find(server => {
        if (server.AuthorisationServers && server.AuthorisationServers.some(as => {
            if (as.CustomerFriendlyName == 'Mock Bank') {
                authServer = as;
                return true;
            }
        })) {
            return server;
        }
    });

    // console.log(foundBank);
    // console.log(authServer);

    // @ts-ignore
    let consentEndPointCollection;
    if (!authServer || !authServer.ApiResources || !authServer.ApiResources.some(ep => {
        if (ep.ApiFamilyType == 'consents') {
            consentEndPointCollection = ep;
            return true;
        }
    })) {
        console.log('This authorisation server is not advertising a consents api collection');
        throw new exception('Authorisation Server does not support consents api family');
    }

    // console.log(consentEndPointCollection);
    //Get the correct consent endpoint and then use that to instantiate the API.
    let consentApiEndpoint;
    if (!consentEndPointCollection || !consentEndPointCollection.ApiDiscoveryEndpoints || !consentEndPointCollection.ApiDiscoveryEndpoints.some(ep => {
        if (ep.ApiEndpoint.match('consents/v1/consents$')) {
            consentApiEndpoint = ep;
            return true;
        }
    })) {
        console.log('This authorisation server is not advertising a consents api collection');
        throw new exception('Authorisation Server does not the correct consent API');
    }


    const consentsApi = new ConsentsApi(
        undefined,
        consentApiEndpoint.ApiEndpoint.split('/consents/v1/consents')[0],
        instance
    );

    //Load the Accounts API

    let accountsEndPointCollection;
    if (!authServer || !authServer.ApiResources || !authServer.ApiResources.some(ep => {
        if (ep.ApiFamilyType == 'accounts') {
            accountsEndPointCollection = ep;
            return true;
        }
    })) {
        console.log('This authorisation server is not advertising an accounts api collection');
        throw new exception('Authorisation Server does not support accounts api family');
    }

    // console.log(accountsEndPointCollection);
    //Get the correct consent endpoint and then use that to instantiate the API.
    let accountsApiEndpoint;
    if (!accountsEndPointCollection || !accountsEndPointCollection.ApiDiscoveryEndpoints || !accountsEndPointCollection.ApiDiscoveryEndpoints.some(ep => {
        if (ep.ApiEndpoint.match('accounts/v1/accounts$')) {
            accountsApiEndpoint = ep;
            return true;
        }
    })) {
        console.log('This authorisation server is not advertising an accounts api collection');
        throw new exception('Authorisation Server does not advertise the correct accounts API');
    }

    const accountsApi = new AccountsApi(
        undefined,
        accountsApiEndpoint.ApiEndpoint.split('/accounts/v1/accounts')[0],
        instance
    );


    async function generateRequest(consentId, usePar = false) {
        const state = crypto.randomBytes(32).toString('hex');
        const nonce = crypto.randomBytes(32).toString('hex');
        const code_verifier = generators.codeVerifier();

        // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
        // it should be httpOnly (not readable by javascript) and encrypted.
        const code_challenge = generators.codeChallenge(code_verifier);

        const claims = {
            id_token: {
                auth_time: {
                    essential: true,
                },
                given_name: {
                    essential: true,
                },

                acr: {
                    value: 'urn:brasil:openbanking:loa2',
                    essential: true
                }
            },
            user_info: {
                auth_time: {
                    essential: true,
                },
                given_name: {
                    essential: true,
                },

                acr: {
                    value: 'urn:brasil:openbanking:loa2',
                    essential: true
                }
            }
        };

        const scope = USE_DYNAMIC_SCOPE ? `openid consent:${consentId} accounts` : 'openid';
        const obj = {
            scope,
            response_type: 'code id_token',
            redirect_uri: 'https://localhost.emobix.co.uk:8443/test/a/obbsb/callback',
            code_challenge,
            code_challenge_method: 'S256',
            response_mode: 'form_post',
            state,
            nonce,
            claims,
            max_age: 900
        };
        console.log(JSON.stringify(obj));
        const requestObject = await fapiClient.requestObject(obj);

        console.log('Request Object ' + requestObject);


        let reference;
        let authUrl;

        if (usePar) {

            try {
                reference = await fapiClient.pushedAuthorizationRequest({
                    request: requestObject
                });
            } catch (e) {
                console.log(e);
            }

            authUrl = await fapiClient.authorizationUrl({ request_uri: reference.request_uri });
            console.log(authUrl);

        } else {
            authUrl = await fapiClient.authorizationUrl({ request: requestObject });
        }
        console.log(authUrl);
        return { authUrl: authUrl + '&scope=' + encodeURIComponent(obj.scope) + '&response_type=' + encodeURIComponent(obj.response_type), code_verifier, state, nonce };
    }

    custom.setHttpOptionsDefaults({
        hooks: {
            beforeRequest: [
                (options) => {
                    console.log('--> REQUEST %s %s', options.method.toUpperCase(), options.url.href);
                    console.log('--> REQUEST HEADERS %o', options.headers);
                    if (options.body) {
                        console.log('--> REQUEST BODY %s', options.body);
                    }
                    if (options.form) {
                        console.log('--> REQUEST FORM %s', options.form);
                    }
                },
            ],
            afterResponse: [
                (response) => {
                    console.log('<-- RESPONSE %i FROM %s %s', response.statusCode, response.request.options.method.toUpperCase(), response.request.options.url.href);
                    console.log('<-- RESPONSE HEADERS %o', response.headers);
                    if (response.body) {
                        console.log('<-- RESPONSE BODY %s', JSON.stringify(response.body));
                    }
                    return response;
                },
            ],
        },
        timeout: 5000,
        https: {
            certificateAuthority: fs.readFileSync(certsPath + 'ca.pem'),
            certificate: fs.readFileSync(certsPath + 'transport.pem'),
            key: fs.readFileSync(certsPath + 'transport.key'),
            rejectUnauthorized: false
        }
    });

    const localIssuer = await Issuer.discover('https://auth.mockbank.poc.raidiam.io/');

    console.log('Discovered issuer %s %O', localIssuer.issuer, localIssuer.metadata);

    const { FAPIClient } = localIssuer;

    const fapiClient = await FAPIClient.fromUri(
        dcrRegistration.data.registration_client_uri,
        dcrRegistration.data.registration_access_token,
        keyset
    );

    console.log('Discovered client %O', fapiClient);

    fapiClient[custom.http_options] = function (options) {
        options.https = {};
        options.https.rejectUnauthorized = false;

        options.https.certificate = fs.readFileSync(certsPath + 'transport.pem'); // <string> | <string[]> | <Buffer> | <Buffer[]>
        options.https.key = fs.readFileSync(certsPath + 'transport.key');
        options.https.certificateAuthority = fs.readFileSync(certsPath + 'ca.pem');// <string> | <string[]> | <Buffer> | <Buffer[]> | <Object[]>
        return options;
    };

    app.use(
        express.urlencoded({
            extended: true
        })
    );

    app.use(cookieParser());


    app.get('/', async (req, res) => {

        res.sendFile(path.join(__dirname, './views', 'index.html'));
    });

    app.use(express.urlencoded({ extended: true }))

    app.post('/test/a/obbsb/callback', async (req, res) => {

        const callbackParams = fapiClient.callbackParams(req);

        const path = '';

        if (!Object.keys(callbackParams).length) {


            console.log('Creating Consent');

            const tokens = await fapiClient.grant({ scope: 'openid consents resources', grant_type: 'client_credentials' });
            console.log(tokens.access_token);

            const introspection = await fapiClient.introspect(tokens.access_token);
            console.log(introspection);

            const oneYearFromNow = new Date();
            oneYearFromNow.setMonth(oneYearFromNow.getMonth() + 2);
            var oneYearAndOneDayFromNow = new Date();

            oneYearAndOneDayFromNow.setFullYear(oneYearAndOneDayFromNow.getFullYear() + 1);
            oneYearAndOneDayFromNow.setMinutes(oneYearAndOneDayFromNow.getMinutes() + 1);


            const createPost = await consentsApi.consentsPostConsents(`${tokens.token_type} ${tokens.access_token}`,
                {
                    data: {
                        permissions: [CreateConsentDataPermissionsEnum.AccountsRead, CreateConsentDataPermissionsEnum.AccountsBalancesRead, CreateConsentDataPermissionsEnum.AccountsTransactionsRead, CreateConsentDataPermissionsEnum.ResourcesRead],
                        expirationDateTime: oneYearFromNow.toISOString(),
                        loggedUser: {
                            document: {
                                identification: '76109277673',
                                rel: 'CPF'
                            }
                        },
                    }
                }).catch(err => {
                    console.log(err);
                });
            console.log(JSON.stringify(createPost.data));

            const consent = await consentsApi.consentsGetConsentsConsentId(createPost.data.data.consentId, `${tokens.token_type} ${tokens.access_token}`);
            console.log('Consent ' + JSON.stringify(consent.data));

            const { authUrl, code_verifier, state, nonce } = await generateRequest(createPost.data.data.consentId, USE_PAR);

            res.cookie('bank.state', state, { path, sameSite: 'none', secure: true });
            res.cookie('bank.nonce', nonce, { path, sameSite: 'none', secure: true });
            //This needs to be encrypted
            res.cookie('bank.code_verifier', code_verifier, { path, sameSite: 'none', secure: true });

            console.log(authUrl);
            return res.redirect(authUrl);
        }

        if (callbackParams.error) {
            return res.json(callbackParams);
        }

        let introspection;
        let tokenSet;
        let accounts;
        let account;
        let balance;
        let overdraftLimit;
        let transactions;

        try {
            // Process Callback
            const state = req.cookies['bank.state'];
            res.cookie('bank.state', null, { path });

            const nonce = req.cookies['bank.nonce'];
            res.cookie('bank.nonce', null, { path });

            const code_verifier = req.cookies['bank.code_verifier'];
            res.cookie('bank.code_verifier', null, { path });

            tokenSet = await fapiClient.callback('https://localhost.emobix.co.uk:8443/test/a/obbsb/callback',
                callbackParams,
                { code_verifier, state, nonce, response_type: 'code id_token' },
                { clientAssertionPayload: { aud: localIssuer.mtls_endpoint_aliases.token_endpoint } });

            console.log(tokenSet);

            introspection = await fapiClient.introspect(tokenSet.access_token);

            accounts = await (await accountsApi.getAccounts(`${tokenSet.token_type} ${tokenSet.access_token}`)).data;
            account = await (await accountsApi.getAccountsAccountId(`${tokenSet.token_type} ${tokenSet.access_token}`, accounts.data[0].accountId)).data;
            balance = await (await accountsApi.getAccountsAccountIdBalances(`${tokenSet.token_type} ${tokenSet.access_token}`, accounts.data[0].accountId)).data;
            // transactions = await (await accountsApi.getAccountsAccountIdTransactions(`${tokenSet.token_type} ${tokenSet.access_token}`, accounts.data[0].accountId)).data;
            //overdraftLimit = await (await accountsApi.getAccountsAccountIdOverdraftLimits(`${tokenSet.token_type} ${tokenSet.access_token}`, accounts.data[0].accountId)).data;

        }
        catch (err) {
            console.log(err);
            return res.json({ status: 'Failed' });
        }

        //Make a client credentials grant

        return res.json({ status: 'Received', introspection: introspection, id_token_claims: tokenSet.claims(), accounts, account, balance, transactions });
    });



    https
        .createServer(
            {
                // ...
                key: fs.readFileSync(certsPath + 'transport.key'),
                cert: fs.readFileSync(certsPath + 'transport.pem'),
                // ...
            },
            app
        )
        .listen(8443);

    console.log('Node.js web server at port 8443 is running..');

})();