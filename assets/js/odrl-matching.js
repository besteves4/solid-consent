
var appURL = null
var userURL = null

function getAppPolicyURL(url) {
    appURL = url;
    console.log(appURL)
    var app1 = document.getElementById('app1');
        if (app1.style.display == 'block') {
            app1.style.display = 'none';
        }
        else {
            app1.style.display = 'block';
        }
}

function getUserPolicyURL(url) {
    userURL = url;
    console.log(userURL)
    var app2 = document.getElementById('app2');
        if (app2.style.display == 'block') {
            app2.style.display = 'none';
        }
        else {
            app2.style.display = 'block';
        }
}

function getTest() {
    FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')
    XSD  = $rdf.Namespace('http://www.w3.org/2001/XMLSchema#')
    RDF = $rdf.Namespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
    RDFS = $rdf.Namespace("http://www.w3.org/2000/01/rdf-schema#")
    ODRL = $rdf.Namespace("http://www.w3.org/ns/odrl/2/")
    DPV = $rdf.Namespace("http://www.w3.org/ns/dpv#")
    ACL = $rdf.Namespace("http://www.w3.org/ns/auth/acl#")
    var timeout = 5000 // 5000 ms timeout
    
    var userPreferenceStore = $rdf.graph()
    var userPreferenceStoreFetcher = new $rdf.Fetcher(userPreferenceStore, timeout)
    var userPermissions = null

    var appPolicyStore = $rdf.graph()
    var appPolicyFetcher = new $rdf.Fetcher(appPolicyStore, timeout)
    var appPermissions = null
    
    var dpvUri = 'https://protect.oeg.fi.upm.es/semantics2021/assets/rdf/dpv.ttl'
    var dpvStore = $rdf.graph()
    var dpvFetcher = new $rdf.Fetcher(dpvStore, timeout)

    var aclReadMapping = [DPV('Use').value, DPV('Collect').value]
    var aclWriteMapping = [DPV('MakeAvailable').value, DPV('Store').value]
  
    userPreferenceStoreFetcher.nowOrWhenFetched(userURL, undefined, function(ok, body, xhr) {
        if (!ok) {
            console.log("Oops, something happened and couldn't fetch data");
        } else {
            appPolicyFetcher.nowOrWhenFetched(appURL, undefined, function(ok, body, xhr) {
                if (!ok) {
                    console.log("Oops, something happened and couldn't fetch data");
                } else {
                    
                    appPermissions = appPolicyStore.statementsMatching(undefined, ODRL('permission'), undefined)
    
                    userPermissions = userPreferenceStore.statementsMatching(undefined, ODRL('permission'), undefined)
                    userProhibitions = userPreferenceStore.statementsMatching(undefined, ODRL('prohibition'), undefined)
    
                    dpvFetcher.nowOrWhenFetched(dpvUri, undefined, function(ok, body, xhr) {
                        if (!ok) {
                            console.log("Oops, something happened and couldn't fetch data");
                        } else {
                            console.log(appPolicyStore)
                            console.log(userURL)
                            for (var i=0; i<appPermissions.length;i++) {
                                appPermission = appPermissions[i]
                    
                                for (var j=0; j<userPermissions.length;j++){
                                    userPermission = userPermissions[j]
            
                                    /* Match personal data target */
                                    var userTargets = userPreferenceStore.statementsMatching(userPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                                    var appTargets = appPolicyStore.statementsMatching(appPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                                    
                                    var getUserTargetsSubclasses = userPreferenceStore.statementsMatching(userPermission.object, ODRL('target'), undefined)
                                    for (var t=0; t<getUserTargetsSubclasses.length;t++) {
                                        subclasses = dpvStore.statementsMatching(undefined, RDFS('subClassOf'), getUserTargetsSubclasses[t].object).map(a => a.subject.value)
                                        userTargets.push(subclasses)
                                    }
    
                                    resultTarget = appTargets.map(a => userTargets.flat().indexOf(a) > -1).every(Boolean)
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
                                        
                                        var getUserPurposesSubclasses = userPreferenceStore.statementsMatching(findUserPurposeConstraint[0].object, ODRL('rightOperand'), undefined)
                                        for (var p=0; p<getUserPurposesSubclasses.length;p++) {
                                            subclasses = dpvStore.statementsMatching(undefined, RDFS('subClassOf'), getUserPurposesSubclasses[p].object).map(a => a.subject.value)
                                            specifiedUserPurposes.push(subclasses)
                                        }
    
                                        resultPurpose = specifiedAppPurposes.map(a => specifiedUserPurposes.flat().indexOf(a) > -1).every(Boolean)
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
                                        // result.value = 'App permission ' + (i+1) + ' matches user preference permission ' + (j+1);
                                        document.getElementById("result").innerText = 'Access authorized';
                                        console.log('App permission ' + (i+1) + ' matches user preference permission ' + (j+1))
                                    } else {
                                        document.getElementById("result").innerText = 'Access denied';
                                        console.log('App permission ' + (i+1) + ' does not match user preference permission ' + (j+1))
                                    }
                                }
                    
                                console.log('test_2')
                            }
    
                        }
                    })
                }
            })
        }
    })
}