var $rdf = require('rdflib');

FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1/')
XSD  = $rdf.Namespace('http://www.w3.org/2001/XMLSchema#')
RDF = $rdf.Namespace("http://www.w3.org/1999/02/22-rdf-syntax-ns#")
RDFS = $rdf.Namespace("http://www.w3.org/2000/01/rdf-schema#")

var uri = 'https://protect.oeg.fi.upm.es/def/gdprif/ontology.ttl'
//var uri = 'https://raw.githubusercontent.com/besteves4/odrl-dpv-acl-profile/main/odrl-dpv-acl-profile.ttl'
var store = $rdf.graph()
var timeout = 5000 // 5000 ms timeout
var fetcher = new $rdf.Fetcher(store, timeout)

fetcher.nowOrWhenFetched(uri, function(ok, body, xhr) {
    if (!ok) {
        console.log("Oops, something happened and couldn't fetch data");
    } else {
        // do something with the data in the store (see below)
        console.log("Fetched https://protect.oeg.fi.upm.es/def/gdprif/ontology.ttl");

        var me = $rdf.sym('https://protect.oeg.fi.upm.es/def/gdprif');
        //var knows = RDF('type')
        var knows = $rdf.sym('http://purl.org/dc/terms/creator')
        var friend = store.each(me, knows)
        console.log(friend)

        var friends = store.statementsMatching(undefined, $rdf.sym('http://purl.org/dc/terms/creator'), undefined)
        for (var i=0; i<friends.length;i++) {
            friend = friends[i]
            console.log(friend.subject.uri) // a person having friends
            console.log(friend.object) // a friend of a person
        }
    }
})