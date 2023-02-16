const fs = require('fs');

const Y = require('yjs')
const syncProtocol = require('y-protocols/dist/sync.cjs')
const awarenessProtocol = require('y-protocols/dist/awareness.cjs')

const encoding = require('lib0/dist/encoding.cjs')
const decoding = require('lib0/dist/decoding.cjs')
const map = require('lib0/dist/map.cjs')

const debounce = require('lodash.debounce')

const callbackHandler = require('./callback.js').callbackHandler
const isCallbackSet = require('./callback.js').isCallbackSet

const Crypto = require('chainpad-crypto')

const CALLBACK_DEBOUNCE_WAIT = parseInt(process.env.CALLBACK_DEBOUNCE_WAIT) || 2000
const CALLBACK_DEBOUNCE_MAXWAIT = parseInt(process.env.CALLBACK_DEBOUNCE_MAXWAIT) || 10000

const wsReadyStateConnecting = 0
const wsReadyStateOpen = 1
const wsReadyStateClosing = 2 // eslint-disable-line
const wsReadyStateClosed = 3 // eslint-disable-line



// disable gc when using snapshots!
const gcEnabled = process.env.GC !== 'false' && process.env.GC !== '0'
const persistenceDir = process.env.YPERSISTENCE
/**
 * @type {{bindState: function(string,WSSharedDoc):void, writeState:function(string,WSSharedDoc):Promise<any>, provider: any}|null}
 */

let persistence = null
if (typeof persistenceDir === 'string') {
  console.info('Persisting documents to "' + persistenceDir + '"')
  persistence = {
    writeState: async (docName, ydoc) => {
      const filepath= persistenceDir +"/" + docName
      console.log("📝 Write to disk " + filepath)
      var file = fs.createWriteStream(filepath)
      file.write(serializeHistory(ydoc.messageHistory))
      file.end()

      if (ydoc.validateKey) {
        const fileMD = fs.createWriteStream(filepath + ".metadata")
        fileMD.write(/*Buffer.from(*/ydoc.validateKey/*).toString('base64')*/)
        fileMD.end()
      }
    },
    readState: (docName) => {
      var result = {}
      const filepath= persistenceDir +"/" + docName
      if (fs.existsSync(filepath)) {
        console.log("📄 Read from disk " + filepath)
        result.history =  deserializeHistory(fs.readFileSync(filepath))
      }
      if (fs.existsSync(filepath + ".metadata")) {
        const metadata =  fs.readFileSync(filepath + ".metadata")
        result.metadata = metadata //new Uint8Array(Buffer.from(metadata, "base64"))I
      }
      return result
    }
  }
}



/**
 * @param {{bindState: function(string,WSSharedDoc):void,
 * writeState:function(string,WSSharedDoc):Promise<any>,provider:any}|null} persistence_
 */
exports.setPersistence = persistence_ => {
  persistence = persistence_
}

/**
 * @return {null|{bindState: function(string,WSSharedDoc):void,
  * writeState:function(string,WSSharedDoc):Promise<any>}|null} used persistence layer
  */
exports.getPersistence = () => persistence

/**
 * Serialize the messageHistory (Array of Uint8Array) to string by using base64
 * encoding
 *
 * @param {messageHistory} Array
 * @return {string}
 */
function serializeHistory(messageHistory) {
  var serialized = []
  for (let elem of messageHistory) {
    serialized.push( Buffer.from(elem).toString('base64'))
  }

  return JSON.stringify(serialized)
}

/**
 * Derialize the serialized messageHistory to an Array of Uint8Array by using
 * base64 encoding
 * @param {messageHistory} Array
 * @return {string}
 */
function deserializeHistory(serialized) {
  var deserialized = []
  for (let elem of JSON.parse(serialized)) {
    deserialized.push(new Uint8Array(Buffer.from(elem, "base64")))
  }

  return deserialized
}

/**
 * @type {Map<string,WSSharedDoc>}
 */
const docs = new Map()
// exporting docs so that others can use it
exports.docs = docs

const messageSync = 0
const messageAwareness = 1
const messageValidateKey = 11 // inner type for the validateKey
const messageCrypto = 100 // outer type for general encrypted updates
const messageAwarenessCrypto = 101 // outer type for encrypted awareness
const messageFullCrypto = 110 // outer type for encrypted ful updates

const messageTypesCrypto = [
  messageCrypto,
  messageAwarenessCrypto,
  messageFullCrypto
]
// const messageAuth = 2
//

/**
 * Note that this function will not be called when encryption is used.
 *
 * @param {Uint8Array} update
 * @param {any} origin
 * @param {WSSharedDoc} doc
 */
const updateHandler = (update, _origin, doc) => {
  console.log("UpdateHandler" + update)
  const encoder = encoding.createEncoder()
  encoding.writeVarUint(encoder, messageSync)
  syncProtocol.writeUpdate(encoder, update)
  const message = encoding.toUint8Array(encoder)
  doc.conns.forEach((_, conn) => send(doc, conn, message))
}

class WSSharedDoc extends Y.Doc {
  /**
   * @param {string} name
   */
  constructor (name) {
    super({ gc: gcEnabled })
    this.name = name
    /**
     * Maps from conn to set of controlled user ids. Delete all user ids from awareness when this conn is closed
     * @type {Map<Object, Set<number>>}
     */
    this.conns = new Map()

    this.messageHistory = []
    /**
     * @type {awarenessProtocol.Awareness}
     */
    this.awareness = new awarenessProtocol.Awareness(this)
    this.awareness.setLocalState(null)
    /**
     * @param {{ added: Array<number>, updated: Array<number>, removed: Array<number> }} changes
     * @param {Object | null} conn Origin is the connection that made the change
     */
    const awarenessChangeHandler = ({ added, updated, removed }, conn) => {
      const changedClients = added.concat(updated, removed)
      if (conn !== null) {
        const connControlledIDs = /** @type {Set<number>} */ (this.conns.get(conn))
        if (connControlledIDs !== undefined) {
          added.forEach(clientID => { connControlledIDs.add(clientID) })
          removed.forEach(clientID => { connControlledIDs.delete(clientID) })
        }
      }
      // broadcast awareness update
      const encoder = encoding.createEncoder()
      encoding.writeVarUint(encoder, messageAwareness)
      encoding.writeVarUint8Array(encoder, awarenessProtocol.encodeAwarenessUpdate(this.awareness, changedClients))
      const buff = encoding.toUint8Array(encoder)
      this.conns.forEach((_, c) => {
        send(this, c, buff)
      })
    }
    this.awareness.on('update', awarenessChangeHandler)
    this.on('update', updateHandler)
    if (isCallbackSet) {
      this.on('update', debounce(
        callbackHandler,
        CALLBACK_DEBOUNCE_WAIT,
        { maxWait: CALLBACK_DEBOUNCE_MAXWAIT }
      ))
    }
  }
}

/**
 * Gets a Y.Doc by name, whether in memory or on disk
 *
 * @param {string} docname - the name of the Y.Doc to find or create
 * @param {boolean} gc - whether to allow gc on the doc (applies only when created)
 * @return {WSSharedDoc}
 */
const getYDoc = (docname, gc = true) => map.setIfUndefined(docs, docname, () => {
  const doc = new WSSharedDoc(docname)
  doc.gc = gc
  if (persistence !== null) {
    const data = persistence.readState(docname)
    if (data.history) { // check if we could read the state from disk
      doc.messageHistory = data.history
    }
    if (data.metadata) { // check if we could read the state from disk
      doc.validateKey = data.metadata
    }
  }
  docs.set(docname, doc)
  return doc
})

exports.getYDoc = getYDoc

/**
 * @param {Uint8Array} message
 * @return {Uint8Array}
 */
const checkAndRemoveSignature = (message, validateKey) => {
  if(!validateKey){
    return new Uint8Array()
  }

  const decoder = decoding.createDecoder(message)
  const OuterMessageType = decoding.readVarUint(decoder)
  const signedCiphertext = decoding.readTailAsUint8Array(decoder)

  const ciphertext = Crypto.Nacl.sign.open(signedCiphertext, validateKey)

  if (!ciphertext) {
    console.error("Could not validate signature:")
    return new Uint8Array()
  }

  // const encoded = Crypto.Nacl.util.encodeUTF8(ciphertext)
  const encoder = encoding.createEncoder()
  encoding.writeVarUint(encoder, OuterMessageType)
  encoding.writeVarUint8Array(encoder, ciphertext)

  return encoding.toUint8Array(encoder)
}

/**
 * @param {any} conn
 * @param {WSSharedDoc} doc
 * @param {Uint8Array} message
 */
const messageListener = (conn, doc, message) => {
  try {
    const encoder = encoding.createEncoder()
    const decoder = decoding.createDecoder(message)
    const messageType = decoding.readVarUint(decoder)

    // if it is encrypted, then we need to decrypt it
    if (messageTypesCrypto.indexOf(messageType) >= 0) {
        // console.log("🔍️ Check signature")
        message = checkAndRemoveSignature(message, doc.validateKey)

        if(message.length === 0) {
          return
        }
    }

    switch (messageType) {
      case messageValidateKey:
        if (!doc.validateKey){
          console.log("🔑 Store validate Key")
          const validateKey = decoding.readVarString(decoder)
          doc.validateKey = Crypto.Nacl.util.decodeBase64(validateKey)
        }
        break

      case messageFullCrypto:
        // If we get the encrypted full state, then reset the history
        console.log("📜 Get full update")
        doc.messageHistory = []
        // no break to read it as normal encrypted message!

      case messageCrypto:
        doc.messageHistory.push(message) // stora the message
        console.log(
          "📥️ Push message "
          + (doc.messageHistory.length - 1) + ": " + message.slice(0,4)
        )
        // no break to send the message anyway

      case messageAwarenessCrypto: // JUST FORWARD
        doc.conns.forEach((_, conn) => send(doc, conn, message)) // broadcast it
        break

      case messageSync:
        console.log("ℹ️  messageSync")
        encoding.writeVarUint(encoder, messageSync)
        syncProtocol.readSyncMessage(decoder, encoder, doc, null)

        // If the `encoder` only contains the type of reply message and no
        // message, there is no need to send the message. When `encoder` only
        // contains the type of reply, its length is 1.
        if (encoding.length(encoder) > 1) {
          send(doc, conn, encoding.toUint8Array(encoder))
        }
        break
      case messageAwareness: {
        console.log("ℹ️  Awareness")
        doc.conns.forEach((_, conn) => send(doc, conn, message)) // broadcast it
        break
      }
    }
  } catch (err) {
    console.error(err)
    doc.emit('error', [err])
  }
}

/**
 * @param {WSSharedDoc} doc
 * @param {any} conn
 */
const closeConn = (doc, conn) => {
  console.log("🚮 Close connection ")
  if (doc.conns.has(conn)) {
    /**
     * @type {Set<number>}
     */
    // @ts-ignore
    const controlledIds = doc.conns.get(conn)
    doc.conns.delete(conn)
    awarenessProtocol.removeAwarenessStates(doc.awareness, Array.from(controlledIds), null)
    if (doc.conns.size === 0 && persistence !== null) {
      // if persisted, we store state and destroy ydocument
      persistence.writeState(doc.name, doc).then(() => {
        doc.destroy()
      })
      docs.delete(doc.name)
    }
  }
  conn.close()
}

/**
 * @param {WSSharedDoc} doc
 * @param {any} conn
 * @param {Uint8Array} m
 */
const send = (doc, conn, m) => {
  if (conn.readyState !== wsReadyStateConnecting && conn.readyState !== wsReadyStateOpen) {
    closeConn(doc, conn)
  }
  try {
    conn.send(m, /** @param {any} err */ err => { err != null && closeConn(doc, conn) })
  } catch (e) {
    closeConn(doc, conn)
  }
}

const pingTimeout = 30000

/**
 * @param {any} conn
 * @param {any} req
 * @param {any} opts
 */
exports.setupWSConnection = (conn, req, { docName = req.url.slice(1).split('?')[0], gc = true } = {}) => {
  console.log("🆕 New connection")
  conn.binaryType = 'arraybuffer'
  // get doc, initialize if it does not exist yet
  const doc = getYDoc(docName, gc)
  doc.conns.set(conn, new Set())
  // listen and reply to events
  conn.on('message', /** @param {ArrayBuffer} message */ message => messageListener(conn, doc, new Uint8Array(message)))

  // Check if connection is still alive
  let pongReceived = true
  const pingInterval = setInterval(() => {
    if (!pongReceived) {
      if (doc.conns.has(conn)) {
        closeConn(doc, conn)
      }
      clearInterval(pingInterval)
    } else if (doc.conns.has(conn)) {
      pongReceived = false
      try {
        conn.ping()
      } catch (e) {
        closeConn(doc, conn)
        clearInterval(pingInterval)
      }
    }
  }, pingTimeout)
  conn.on('close', () => {
    closeConn(doc, conn)
    clearInterval(pingInterval)
  })
  conn.on('pong', () => {
    pongReceived = true
  })
  // put the following in a variables in a block so the interval handlers don't keep in in
  // scope
  {
    const awarenessStates = doc.awareness.getStates()
    if (awarenessStates.size > 0) {
      const encoder = encoding.createEncoder()
      encoding.writeVarUint(encoder, messageAwareness)
      encoding.writeVarUint8Array(encoder, awarenessProtocol.encodeAwarenessUpdate(doc.awareness, Array.from(awarenessStates.keys())))
      send(doc, conn, encoding.toUint8Array(encoder))
    }
  }

  var i = 0
  doc.messageHistory.forEach(message => {
    send(doc, conn, message)
    console.log("📤️ Send message " + (i++) + ": " + message.slice(0,4))
  }
  )
}
