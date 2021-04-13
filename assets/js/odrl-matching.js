var $rdf = require('rdflib');

FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')
XSD  = $rdf.Namespace('http://www.w3.org/2001/XMLSchema#')
RDF = $rdf.Namespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
RDFS = $rdf.Namespace("http://www.w3.org/2000/01/rdf-schema#")
ODRL = $rdf.Namespace("http://www.w3.org/ns/odrl/2/")
DPV = $rdf.Namespace("http://www.w3.org/ns/dpv#")
ACL = $rdf.Namespace("http://www.w3.org/ns/auth/acl#")

var timeout = 5000 // 5000 ms timeout

var userPreferenceUri = 'http://localhost:9000/assets/rdf/user-preference-ex-1.ttl'
var userPreferenceStore = $rdf.graph()
var userPreferenceStoreFetcher = new $rdf.Fetcher(userPreferenceStore, timeout)
var userPermissions = null

var appPolicyUri = 'http://localhost:9000/assets/rdf/app-policy-ex-2.ttl'
var appPolicyStore = $rdf.graph()
var appPolicyFetcher = new $rdf.Fetcher(appPolicyStore, timeout)
var appPermissions = null

var aclReadMapping = [DPV('Use').value, DPV('Collect').value]
var aclWriteMapping = [DPV('MakeAvailable').value]

userPreferenceStoreFetcher.nowOrWhenFetched(userPreferenceUri, function(ok, body, xhr) {
    if (!ok) {
        console.log("Oops, something happened and couldn't fetch data");
    } else {

        appPolicyFetcher.nowOrWhenFetched(appPolicyUri, function(ok, body, xhr) {
            if (!ok) {
                console.log("Oops, something happened and couldn't fetch data");
            } else {
                userPermissions = userPreferenceStore.statementsMatching(undefined, ODRL('permission'), undefined)
                appPermissions = appPolicyStore.statementsMatching(undefined, ODRL('permission'), undefined)

                for (var i=0; i<appPermissions.length;i++) {
                    appPermission = appPermissions[i]
        
                    for (var j=0; j<userPermissions.length;j++){
                        userPermission = userPermissions[j]

                        /* Match personal data target */
                        var userTargets = userPreferenceStore.statementsMatching(userPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                        var appTargets = appPolicyStore.statementsMatching(appPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                        resultTarget = appTargets.map(a => userTargets.indexOf(a) > -1).every(Boolean)
                        if(!resultTarget){
                            console.log("Access Denied at target")
                        }

                        /* Match processing actions */
                        var userActions = userPreferenceStore.statementsMatching(userPermission.object, ODRL('action'), undefined).map(a => a.object.value)
                        var appActions = appPolicyStore.statementsMatching(appPermission.object, ODRL('action'), undefined).map(a => a.object.value)
                        var mappedAppActions = appActions.map(
                            function(a){
                                if(aclReadMapping.indexOf(a) > -1){
                                    return a.replace(a, ACL('Read').value);
                                } else {
                                    return a;
                                }
                            }
                        );
                        mappedAppActions = mappedAppActions.map(
                            function(a){
                                if(aclWriteMapping.indexOf(a) > -1){
                                    return a.replace(a, ACL('Write').value);
                                } else {
                                    return a;
                                }
                            }
                        );
                        resultActions = mappedAppActions.map(a => userActions.indexOf(a) > -1).every(Boolean)
                        if(!resultActions){
                            console.log("Access Denied at action")
                        }

                        /* Match purpose constraint */
                        var userConstraint = userPreferenceStore.statementsMatching(userPermission.object, ODRL('constraint'), undefined)
                        var appConstraint = appPolicyStore.statementsMatching(appPermission.object, ODRL('constraint'), undefined)

                        var userPurpose = userPreferenceStore.statementsMatching(userConstraint.object, undefined, DPV('Purpose'))
                        var appPurpose = appPolicyStore.statementsMatching(appConstraint.object, undefined, DPV('Purpose'))
                        
                        findUserPurposeConstraint = []
                        findAppPurposeConstraint = []
                        resultPurpose = false
                        if(userPurpose.length > 0 && appPurpose.length > 0){
                            for (var c=0; c<userConstraint.length;c++) {
                                if(userConstraint[c].object.value == userPurpose[0].subject.value){
                                    findUserPurposeConstraint.push(userConstraint[c])
                                }
                            }

                            for (var c=0; c<appConstraint.length;c++) {
                                if(appConstraint[c].object.value == appPurpose[0].subject.value){
                                    findAppPurposeConstraint.push(appConstraint[c])
                                }
                            }

                            var specifiedUserPurposes = userPreferenceStore.statementsMatching(findUserPurposeConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                            var specifiedAppPurposes = appPolicyStore.statementsMatching(findAppPurposeConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                            resultPurpose = specifiedAppPurposes.map(a => specifiedUserPurposes.indexOf(a) > -1).every(Boolean)
                            if(!resultPurpose){
                                console.log("Access Denied at purpose")
                            }
                        }

                        /* Match recipient constraint */
                        var userRecipient = userPreferenceStore.statementsMatching(userConstraint.object, undefined, DPV('Recipient'))
                        findUserRecipientConstraint = []
                        for (var c=0; c<userConstraint.length;c++) {
                            if(userConstraint[c].object.value == userRecipient[0].subject.value){
                                findUserRecipientConstraint.push(userConstraint[c])
                            }
                        }

                        var appRecipient = appPolicyStore.statementsMatching(appConstraint.object, undefined, DPV('Recipient'))
                        findAppRecipientConstraint = []
                        for (var c=0; c<appConstraint.length;c++) {
                            if(appConstraint[c].object.value == appRecipient[0].subject.value){
                                findAppRecipientConstraint.push(appConstraint[c])
                            }
                        }

                        if(findUserRecipientConstraint.length > 0 && findAppRecipientConstraint.length > 0){ // if recipient is defined
                            var specifiedUserRecipients = userPreferenceStore.statementsMatching(findUserRecipientConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                            var specifiedAppRecipients = appPolicyStore.statementsMatching(findAppRecipientConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                            resultRecipient = specifiedAppRecipients.map(a => specifiedUserRecipients.indexOf(a) > -1).every(Boolean)
                            if(!resultRecipient){
                                console.log("Access Denied at recipient")
                            }
                        }

                        if(resultTarget && resultActions && resultPurpose && resultRecipient){
                            console.log('App permission ' + (i+1) + ' matches user preference permission ' + (j+1))
                        } else {
                            console.log('App permission ' + (i+1) + ' does not match user preference permission ' + (j+1))
                        }
                    }
        
                    console.log('test_2')
                }
            }
        })
    }
})