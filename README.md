# BLTEReader
This module provides a NodeJS reader for the BLTE file-format found in games by Blizzard Entertainment. The BLTEReader class is an extension of the [Bufo](https://github.com/Kruithne/node-bufo) buffer utility class.

## Installing
```
npm install node-blte
```

## Usage
```javascript
// Import module, naturally...
const BLTEReader = require('node-blte');

// Register encryption keys (for encrypted blocks).
BLTEReader.registerDecryptionKeys({
    '213D67C1543A63A9': '1F8D467F5D6D411F8A548B6329A5087E',
    '2BB68ACDC6254F79': '76583BDACD5257A3F73D1598A2CA2D99'
});

let key = 'a19e2d57adf9830d989e3dad7dd56cec';
let buffer = obtainBufferSomehow();

// Create a new BLTEReader from an existing buffer (or Bufo instance).
let reader = new BLTEReader(buffer, key);

// `reader` can now be used just like a normal Bufo instance, and will automatically
// decompress and decrypt blocks (using given keys) as needed.

// If you need all blocks to be pre-processed (buffer transfer, etc), call `readAllBlocks()` first.
```