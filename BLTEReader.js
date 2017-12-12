/*!
	BLTEReader (https://github.com/Kruithne/node-blte)
	Author: Kruithne <kruithne@gmail.com>
	License: MIT
 */

const Bufo = require('bufo');
const md5 = require('md5');
const zlib = require('zlib');
const util = require('util');
const bytey = require('bytey');
const Salsa20 = require('./salsa20');

const ENC_TYPE_SALSA20 = 0x53;
const ENC_TYPE_ARC4 = 0x41;
const EMPTY_HASH = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
const KEY_RING = {};

/**
 * Error thrown by the BLPFile class.
 * @class BLPError
 */
class BLTEError extends Error {
	constructor(id, message, ...args) {
		message = 'BLTE: ' + util.format(message, args);
		super(message);
		this.errID = id;
		this.stack = (new Error(message)).stack;
		this.name = this.constructor.name;
	}
}

class BLTEReader extends Bufo {
	/**
	 * Create a new BLTEReader instance.
	 * @param {Buffer|Bufo} buffer Raw buffer.
	 * @param {string} hash MD5 content hash.
	 */
	constructor(buffer, hash) {
		super([]);

		// Wrap the raw buffer in a Bufo instance.
		if (buffer instanceof Buffer)
			buffer = new Bufo(buffer);

		this.rawData = buffer;
		this.blockIndex = 0;

		let size = buffer.byteLength;
		if (size < 8)
			throw new BLTEError(0x1, 'Not enough data. (8)');

		let magic = buffer.readInt32();
		if (magic !== 0x45544c42)
			throw new BLTEError(0x2, 'Invalid data (magic).');

		let headerSize = buffer.readInt32(1, Bufo.ENDIAN_BIG);

		let origPos = buffer.offset;
		buffer.seek(0);

		let newHash = md5(headerSize > 0 ? buffer.readUInt8(headerSize) : buffer.readUInt8(size));
		if (newHash !== hash)
			throw new BLTEError(0x3, 'Hash mismatch. Expected %s, got %s.', hash, newHash);

		buffer.seek(origPos);

		let numBlocks = 1;
		if (headerSize > 0) {
			if (size < 12)
				throw new BLTEError(0x4, 'Not enough data (12)');

			let fcBytes = buffer.readUInt8(4);

			numBlocks = fcBytes[1] << 16 | fcBytes[2] << 8 | fcBytes[3] << 0;

			if (fcBytes[0] !== 0x0F || numBlocks === 0)
				throw new BLTEError(0x5, 'Invalid table format.');

			let frameHeaderSize = 24 * numBlocks + 12;
			if (headerSize !== frameHeaderSize)
				throw new BLTEError(0x6, 'Invalid header size.');

			if (size < frameHeaderSize)
				throw new BLTEError(0x7, 'Not enough data (frameHeader)');
		}

		this.blocks = [];
		let allocSize = 0;

		for (let i = 0; i < numBlocks; i++) {
			let block = {};
			if (headerSize !== 0) {
				block.CompSize = buffer.readInt32(1, Bufo.ENDIAN_BIG);
				block.DecompSize = buffer.readInt32(1, Bufo.ENDIAN_BIG);
				block.Hash = buffer.readUInt8(16);
			} else {
				block.CompSize = size - 8;
				block.DecompSize = size - 9;
				block.Hash = EMPTY_HASH;
			}

			allocSize += block.DecompSize;
			this.blocks[i] = block;
		}

		this.raw = Buffer.alloc(allocSize);
		this._processBlock();
	}

	_read(func, size, count) {
		count = count || 1;
		while (this.offset + (size * count) > this.lastWriteOffset)
			this._processBlock();

		return super._read(func, size, count);
	}

	readAllBlocks() {
		while (this.blockIndex < this.blocks.length)
			this._processBlock();
	}

	_processBlock() {
		if (this.blockIndex === this.blocks.length)
			return false;

		let oldPos = this.offset;
		this.seek(this.lastWriteOffset);

		let block = this.blocks[this.blockIndex];
		block.Data = this.rawData.readBufo(block.CompSize);

		if (!bytey.isByteArrayEqual(block.Hash, EMPTY_HASH)) {
			let blockHash = md5(block.Data.readUInt8(block.CompSize), { asBytes: true });
			block.Data.seek(0);

			if (!bytey.isByteArrayEqual(blockHash, block.Hash))
				throw new BLTEError(0x8, 'Block data hash mismatch.');
		}

		this._handleBlock(block.Data, this.blockIndex);
		this.blockIndex++;

		this.seek(oldPos);
	}

	_handleBlock(data, index) {
		let flag = data.readUInt8();

		switch (flag) {
			case 0x45: // Encrypted
				let decrypted = BLTEReader._decryptBlock(data, index);
				this._handleBlock(decrypted, index);
				break;

			case 0x46: // Frame (Recursive)
				throw new BLTEError(0x9, 'No frame decoder implemented.');
				break;

			case 0x4E: // Frame (Normal)
				this.writeBuffer(data);
				break;

			case 0x5A: // Compressed
				this._decompressBlock(data, index);
				break;
		}
	}

	_decompressBlock(data, index) {
		let decompressed = new Bufo(zlib.inflateSync(data.readBuffer()));
		let expectedSize = this.blocks[index].DecompSize;
		if (decompressed.byteLength > expectedSize) {
			// Reallocate buffer to compensate.
			let newBuffer = new Bufo((this.byteLength - expectedSize) + decompressed.byteLength);
			newBuffer.writeBuffer(this);
			this.raw = newBuffer.raw;
		}
		this.writeBuffer(decompressed);
	}

	static _decryptBlock(data, index) {
		let keyNameSize = data.readUInt8();

		if (keyNameSize === 0 || keyNameSize !== 8)
			throw new BLTEError(0xA, 'Unexpected keyNameSize => %d', keyNameSize);

		let keyNameBytes = bytey.byteArrayToHexString(data.readUInt8(keyNameSize)).toLowerCase();
		let ivSize = data.readUInt8();

		if (ivSize !== 4)
			throw new BLTEError(0xB, 'Unexpected ivSize => %d', ivSize);

		let ivShort = data.readUInt8(ivSize);
		if (data.byteLength <= data.offset)
			throw new BLTEError(0xC, 'Unexpected EoS before encryption flag.');

		let encryptType = data.readUInt8();
		if (encryptType !== ENC_TYPE_SALSA20 && encryptType !== ENC_TYPE_ARC4)
			throw new BLTEError(0xD, 'Unexpected encryption type %s', encryptType);

		for (let shift = 0, i = 0; i < 4; shift += 8, i++)
			ivShort[i] ^= (index >> shift) & 0xFF;

		let key = KEY_RING[keyNameBytes];
		if (key === undefined)
			throw new BLTEError(0xE, 'Unknown key %s', keyNameBytes);

		if (encryptType === ENC_TYPE_ARC4)
			throw new BLTEError(0xF, 'Arc4 decryption not implemented.');

		let nonce = [];
		for (let i = 0; i < 8; i++)
			nonce[i] = (i < ivShort.length ? ivShort[i] : 0x0);

		let instance = new Salsa20(16, nonce, key);
		return instance.process(data.readBufo());
	}

	/**
	 * Add a set of keys used for decryption.
	 * @param {object} keys
	 */
	static registerDecryptionKeys(keys) {
		for (let keyName in keys) {
			// Skip extended prototype...
			if (!keys.hasOwnProperty(keyName))
				continue;

			// Ensure we have a valid key length.
			if (keyName.length !== 16)
				throw new BLTEError(0x10, 'Encryption key names are expected to be 8-bytes (16 length string).');

			let key = keys[keyName];
			if (key.length !== 32)
				throw new BLTEError(0x11, 'Encryption keys are expected to be 16-bytes (32 length string).');

			// Store in static key ring.
			KEY_RING[keyName.toLowerCase()] = bytey.hexStringToByteArray(key);
		}
	}
}

module.exports = BLTEReader;