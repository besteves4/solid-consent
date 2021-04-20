
var appURL = null
var userURL = null

function getAppPolicyURL(url) {
    appURL = url;
    console.log(appURL)

    const splits = url.split('-')
    policy = splits[splits.length - 1].split('.')

    var app1 = document.getElementById('app1');
    var app2 = document.getElementById('app2');

    if(policy[0] == "1"){
        app1.style.display = 'block';
        app2.style.display = 'none';
    } else if (policy[0] == "2"){
        app1.style.display = 'none';
        app2.style.display = 'block';
    }
}

function getUserPolicyURL(url) {
    userURL = url;
    console.log(userURL)

    const splits = url.split('-')
    policy = splits[splits.length - 1].split('.')

    var user1 = document.getElementById('user1');
    var user2 = document.getElementById('user2');

    if(policy[0] == "1"){
        user1.style.display = 'block';
        user2.style.display = 'none';
    } else if (policy[0] == "2"){
        user1.style.display = 'none';
        user2.style.display = 'block';
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
                            console.log(userURL)
                            for (var i=0; i<appPermissions.length;i++) {
                                appPermission = appPermissions[i]
                    
                                for (var j=0; j<userPermissions.length;j++){
                                    userPermission = userPermissions[j]
            
                                    /* Match personal data target */
                                    var userPermissionTargets = userPreferenceStore.statementsMatching(userPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                                    var appPermissionTargets = appPolicyStore.statementsMatching(appPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                                    
                                    var getUserTargetsPermissionSubclasses = userPreferenceStore.statementsMatching(userPermission.object, ODRL('target'), undefined)
                                    for (var t=0; t<getUserTargetsPermissionSubclasses.length;t++) {
                                        subclasses = dpvStore.statementsMatching(undefined, RDFS('subClassOf'), getUserTargetsPermissionSubclasses[t].object).map(a => a.subject.value)
                                        userPermissionTargets.push(subclasses)
                                    }
    
                                    resultPermissionTarget = appPermissionTargets.map(a => userPermissionTargets.flat().indexOf(a) > -1).every(Boolean)
                                    if(!resultPermissionTarget){
                                        console.log("Access Denied at target")
                                    }
    
                                    
            
                                    /* Match processing actions */
                                    var userPermissionActions = userPreferenceStore.statementsMatching(userPermission.object, ODRL('action'), undefined).map(a => a.object.value)
                                    var appPermissionActions = appPolicyStore.statementsMatching(appPermission.object, ODRL('action'), undefined).map(a => a.object.value)
                                    var mappedAppPermissionActions = appPermissionActions.map(
                                        function(a){
                                            if(aclReadMapping.indexOf(a) > -1){
                                                return a.replace(a, ACL('Read').value);
                                            } else {
                                                return a;
                                            }
                                        }
                                    );
                                    mappedAppPermissionActions = mappedAppPermissionActions.map(
                                        function(a){
                                            if(aclWriteMapping.indexOf(a) > -1){
                                                return a.replace(a, ACL('Write').value);
                                            } else {
                                                return a;
                                            }
                                        }
                                    );
                                    resultPermissionActions = mappedAppPermissionActions.map(a => userPermissionActions.indexOf(a) > -1).every(Boolean)
                                    if(!resultPermissionActions){
                                        console.log("Access Denied at action")
                                    }
            
                                    /* Match purpose constraint */
                                    var userPermissionConstraint = userPreferenceStore.statementsMatching(userPermission.object, ODRL('constraint'), undefined)
                                    var appPermissionConstraint = appPolicyStore.statementsMatching(appPermission.object, ODRL('constraint'), undefined)
                                    
                                    var userPermissionPurpose = userPreferenceStore.statementsMatching(userPermissionConstraint.object, undefined, DPV('Purpose'))
                                    var appPermissionPurpose = appPolicyStore.statementsMatching(appPermissionConstraint.object, undefined, DPV('Purpose'))
                                    
                                    findUserPermissionPurposeConstraint = []
                                    findAppPermissionPurposeConstraint = []
                                    resultPermissionPurpose = false
                                    if(userPermissionPurpose.length > 0 && appPermissionPurpose.length > 0){
                                        for (var c=0; c<userPermissionConstraint.length;c++) {
                                            if(userPermissionConstraint[c].object.value == userPermissionPurpose[0].subject.value){
                                                findUserPermissionPurposeConstraint.push(userPermissionConstraint[c])
                                            }
                                        }
            
                                        for (var c=0; c<appPermissionConstraint.length;c++) {
                                            if(appPermissionConstraint[c].object.value == appPermissionPurpose[0].subject.value){
                                                findAppPermissionPurposeConstraint.push(appPermissionConstraint[c])
                                            }
                                        }
            
                                        var specifiedUserPermissionPurposes = userPreferenceStore.statementsMatching(findUserPermissionPurposeConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        var specifiedAppPermissionPurposes = appPolicyStore.statementsMatching(findAppPermissionPurposeConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        
                                        var getUserPermissionPurposesSubclasses = userPreferenceStore.statementsMatching(findUserPermissionPurposeConstraint[0].object, ODRL('rightOperand'), undefined)
                                        for (var p=0; p<getUserPermissionPurposesSubclasses.length;p++) {
                                            subclasses = dpvStore.statementsMatching(undefined, RDFS('subClassOf'), getUserPermissionPurposesSubclasses[p].object).map(a => a.subject.value)
                                            specifiedUserPermissionPurposes.push(subclasses)
                                        }
    
                                        resultPermissionPurpose = specifiedAppPermissionPurposes.map(a => specifiedUserPermissionPurposes.flat().indexOf(a) > -1).every(Boolean)
                                        if(!resultPermissionPurpose){
                                            console.log("Access Denied at purpose")
                                        }
                                    }
            
                                    /* Match recipient constraint */
                                    var userPermissionRecipient = userPreferenceStore.statementsMatching(userPermissionConstraint.object, undefined, DPV('Recipient'))
                                    var appPermissionRecipient = appPolicyStore.statementsMatching(appPermissionConstraint.object, undefined, DPV('Recipient'))

                                    findUserPermissionRecipientConstraint = []
                                    findAppPermissionRecipientConstraint = []
                                    resultPermissionRecipient = null
                                    if(userPermissionRecipient.length > 0 && appPermissionRecipient.length > 0){
                                        for (var c=0; c<userPermissionConstraint.length;c++) {
                                            if(userPermissionConstraint[c].object.value == userPermissionRecipient[0].subject.value){
                                                findUserPermissionRecipientConstraint.push(userPermissionConstraint[c])
                                            }
                                        }
                                        
                                        for (var c=0; c<appPermissionConstraint.length;c++) {
                                            if(appPermissionConstraint[c].object.value == appPermissionRecipient[0].subject.value){
                                                findAppPermissionRecipientConstraint.push(appPermissionConstraint[c])
                                            }
                                        }

                                        var specifiedUserPermissionRecipients = userPreferenceStore.statementsMatching(findUserPermissionRecipientConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        var specifiedAppPermissionRecipients = appPolicyStore.statementsMatching(findAppPermissionRecipientConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        
                                        resultPermissionRecipient = specifiedAppPermissionRecipients.map(a => specifiedUserPermissionRecipients.indexOf(a) > -1).every(Boolean)
                                        if(!resultPermissionRecipient){
                                            console.log("Access Denied at recipient")
                                        }
                                    }

                                    console.log(resultPermissionRecipient)
                                    if(resultPermissionRecipient == null){
                                        if(resultPermissionTarget && resultPermissionActions && resultPermissionPurpose){
                                            // result.value = 'App permission ' + (i+1) + ' matches user preference permission ' + (j+1);
                                            document.getElementById("result").innerText = 'Access authorized';
                                            document.getElementById("result").style.color = 'green';
                                            console.log('App permission ' + (i+1) + ' matches user preference permission ' + (j+1))
                                        } else {
                                            document.getElementById("result").innerText = 'Access denied';
                                            document.getElementById("result").style.color = 'red';
                                            console.log('App permission ' + (i+1) + ' does not match user preference permission ' + (j+1))
                                        }
                                    } else {
                                        if(resultPermissionTarget && resultPermissionActions && resultPermissionPurpose && resultPermissionRecipient){
                                            // result.value = 'App permission ' + (i+1) + ' matches user preference permission ' + (j+1);
                                            document.getElementById("result").innerText = 'Access authorized';
                                            document.getElementById("result").style.color = 'green';
                                            console.log('App permission ' + (i+1) + ' matches user preference permission ' + (j+1))
                                        } else {
                                            document.getElementById("result").innerText = 'Access denied';
                                            document.getElementById("result").style.color = 'red';
                                            console.log('App permission ' + (i+1) + ' does not match user preference permission ' + (j+1))
                                        }
                                    }
                                }
                    
                                for (var k=0; k<userProhibitions.length;k++){
                                    userProhibition = userProhibitions[k]
            
                                    /* Match personal data target */
                                    var userProhibitionTargets = userPreferenceStore.statementsMatching(userProhibition.object, ODRL('target'), undefined).map(a => a.object.value)
                                    var appPermissionTargets = appPolicyStore.statementsMatching(appPermission.object, ODRL('target'), undefined).map(a => a.object.value)
                                    
                                    var getUserTargetsProhibitionSubclasses = userPreferenceStore.statementsMatching(userProhibition.object, ODRL('target'), undefined)
                                    for (var t=0; t<getUserTargetsProhibitionSubclasses.length;t++) {
                                        subclasses = dpvStore.statementsMatching(undefined, RDFS('subClassOf'), getUserTargetsProhibitionSubclasses[t].object).map(a => a.subject.value)
                                        userProhibitionTargets.push(subclasses)
                                    }
    
                                    resultProhibitionTarget = appPermissionTargets.map(a => userProhibitionTargets.flat().indexOf(a) > -1).every(Boolean)
                                    if(resultProhibitionTarget){
                                        console.log("User prohibits target data")
                                    }                                    
            
                                    /* Match processing actions */
                                    var userProhibitionActions = userPreferenceStore.statementsMatching(userProhibition.object, ODRL('action'), undefined).map(a => a.object.value)
                                    var appPermissionActions = appPolicyStore.statementsMatching(appPermission.object, ODRL('action'), undefined).map(a => a.object.value)
                                    var mappedAppPermissionActions = appPermissionActions.map(
                                        function(a){
                                            if(aclReadMapping.indexOf(a) > -1){
                                                return a.replace(a, ACL('Read').value);
                                            } else {
                                                return a;
                                            }
                                        }
                                    );
                                    mappedAppPermissionActions = mappedAppPermissionActions.map(
                                        function(a){
                                            if(aclWriteMapping.indexOf(a) > -1){
                                                return a.replace(a, ACL('Write').value);
                                            } else {
                                                return a;
                                            }
                                        }
                                    );
                                    resultProhibitionActions = mappedAppPermissionActions.map(a => userProhibitionActions.indexOf(a) > -1).every(Boolean)
                                    if(resultProhibitionActions){
                                        console.log("User prohibits action operations")
                                    }
            
                                    /* Match purpose constraint */
                                    var userProhibitionConstraint = userPreferenceStore.statementsMatching(userProhibition.object, ODRL('constraint'), undefined)
                                    var appPermissionConstraint = appPolicyStore.statementsMatching(appPermission.object, ODRL('constraint'), undefined)
                                    
                                    var userProhibitionPurpose = userPreferenceStore.statementsMatching(userProhibitionConstraint.object, undefined, DPV('Purpose'))
                                    var appPermissionPurpose = appPolicyStore.statementsMatching(appPermissionConstraint.object, undefined, DPV('Purpose'))
                                    
                                    findUserProhibitionPurposeConstraint = []
                                    findAppPermissionPurposeConstraint = []
                                    resultProhibitionPurpose = false
                                    if(userProhibitionPurpose.length > 0 && appPermissionPurpose.length > 0){
                                        for (var c=0; c<userProhibitionConstraint.length;c++) {
                                            if(userProhibitionConstraint[c].object.value == userProhibitionPurpose[0].subject.value){
                                                findUserProhibitionPurposeConstraint.push(userProhibitionConstraint[c])
                                            }
                                        }
            
                                        for (var c=0; c<appPermissionConstraint.length;c++) {
                                            if(appPermissionConstraint[c].object.value == appPermissionPurpose[0].subject.value){
                                                findAppPermissionPurposeConstraint.push(appPermissionConstraint[c])
                                            }
                                        }
            
                                        var specifiedUserProhibitionPurposes = userPreferenceStore.statementsMatching(findUserProhibitionPurposeConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        var specifiedAppPermissionPurposes = appPolicyStore.statementsMatching(findAppPermissionPurposeConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        
                                        var getUserProhibitionPurposesSubclasses = userPreferenceStore.statementsMatching(findUserProhibitionPurposeConstraint[0].object, ODRL('rightOperand'), undefined)
                                        for (var p=0; p<getUserProhibitionPurposesSubclasses.length;p++) {
                                            subclasses = dpvStore.statementsMatching(undefined, RDFS('subClassOf'), getUserProhibitionPurposesSubclasses[p].object).map(a => a.subject.value)
                                            specifiedUserProhibitionPurposes.push(subclasses)
                                        }
    
                                        resultProhibitionPurpose = specifiedAppPermissionPurposes.map(a => specifiedUserProhibitionPurposes.flat().indexOf(a) > -1).every(Boolean)
                                        if(resultProhibitionPurpose){
                                            console.log("User prohibits specified purposes")
                                        }
                                    }
            
                                    /* Match recipient constraint */
                                    var userProhibitionRecipient = userPreferenceStore.statementsMatching(userProhibitionConstraint.object, undefined, DPV('Recipient'))
                                    var appPermissionRecipient = appPolicyStore.statementsMatching(appPermissionConstraint.object, undefined, DPV('Recipient'))

                                    findUserProhibitionRecipientConstraint = []
                                    findAppPermissionRecipientConstraint = []
                                    resultProhibitionRecipient = null
                                    if(userProhibitionRecipient.length > 0 && appPermissionRecipient.length > 0){
                                        for (var c=0; c<userProhibitionConstraint.length;c++) {
                                            if(userProhibitionConstraint[c].object.value == userProhibitionRecipient[0].subject.value){
                                                findUserProhibitionRecipientConstraint.push(userProhibitionConstraint[c])
                                            }
                                        }
                                        
                                        for (var c=0; c<appPermissionConstraint.length;c++) {
                                            if(appPermissionConstraint[c].object.value == appPermissionRecipient[0].subject.value){
                                                findAppPermissionRecipientConstraint.push(appPermissionConstraint[c])
                                            }
                                        }

                                        var specifiedUserProhibitionRecipients = userPreferenceStore.statementsMatching(findUserProhibitionRecipientConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        var specifiedAppPermissionRecipients = appPolicyStore.statementsMatching(findAppPermissionRecipientConstraint[0].object, ODRL('rightOperand'), undefined).map(a => a.object.value)
                                        
                                        resultProhibitionRecipient = specifiedAppPermissionRecipients.map(a => specifiedUserProhibitionRecipients.indexOf(a) > -1).every(Boolean)
                                        if(resultProhibitionRecipient){
                                            console.log("User prohibits specified recipients")
                                        }
                                    }
                                    
                                    if(resultProhibitionRecipient == null){
                                        if(resultProhibitionTarget && resultProhibitionActions && resultProhibitionPurpose){
                                            document.getElementById("result").innerText = 'Access denied';
                                            document.getElementById("result").style.color = 'red';
                                        } else {
                                            document.getElementById("result").innerText = 'Access authorized';
                                            document.getElementById("result").style.color = 'green';
                                        }
                                    } else {
                                        if(resultProhibitionTarget && resultProhibitionActions && resultProhibitionPurpose && resultProhibitionRecipient){
                                            document.getElementById("result").innerText = 'Access denied';
                                            document.getElementById("result").style.color = 'red';
                                        } else {
                                            document.getElementById("result").innerText = 'Access authorized';
                                            document.getElementById("result").style.color = 'green';
                                        }
                                    }
                                }
                            }
    
                        }
                    })
                }
            })
        }
    })
}