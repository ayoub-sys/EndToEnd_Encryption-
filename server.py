#! /usr/bin/python3 

import json 
from crypt import methods
import bson
from flask import Flask
from flask import request
import json
import pymongo
from pymongo import MongoClient
from bson import json_util

app = Flask(__name__)


try:
    conn=MongoClient('localhost',27017)
         
except:
     print('failure')

'''db=conn.publishedKeys
collection=db.collection
emp={
    "name":"hello",
    "prenom":"how"
}
rec=collection.insert_one(emp)
cursor=collection.find()
for record in cursor:
    print(record)'''

@app.route('/login',methods=['POST'])
def publishKeys():
    emp=request.get_json()
    db=conn.publishedKeys
    col=db.collection
    cursor=col.insert_one(emp)
    #print(emp)
    return 'ok'


@app.route('/getKeys',methods=['GET'])
def extract():
    name=request.args.get('username')

    db=conn.publishedKeys
    extract=db.collection.find({"name":name})
    for data in extract:

        key=json.loads(json_util.dumps(data))
        print(type(key))
        return key 
        #return key_json 

#extract()

@app.route('/postMessage',methods=['POST'])
def postMesg():
    msg=request.get_json()
    db=conn.publishedKeys
    col=db.message
    cursor=col.insert_one(msg)
    #print(emp)
    return 'ok msg loaded in db'


@app.route('/getMessage',methods=['GET'])
def getMesg():
    #name=request.args.get('readFlag')

    db=conn.publishedKeys
    extract=db.message.find({"flag":1})
    for data in extract:

        mesg=json.loads(json_util.dumps(data))
        print(type(mesg))
        print(mesg)
        return mesg  
        #return key_json 

@app.route('/postCipher',methods=["POST"])
def postCypher():
    msg=request.get_json()
    db=conn.publishedKeys
    col=db.Message
    cursor=col.insert_one(msg)
    #print(emp)
    return 'ok msg loaded in db'

@app.route('/getCipher')
def getCypher():
    name1=request.args.get('from')
    
    db=conn.publishedKeys
    extract=db.Message.find({"from":name1,"flag":1})
    for data in extract:

        key=json.loads(json_util.dumps(data))
        print(type(key))
        return key

@app.route('/updateFlag',methods=['POST'])
def updateCypher():
    name1=request.args.get('from')
    db=conn.publishedKeys
    myquery = { "from": name1,"flag":1 }
    newvalues = { "$set": { "flag": 0 } }
    db.Message.update_one(myquery,newvalues)
    return 'ok updated'



