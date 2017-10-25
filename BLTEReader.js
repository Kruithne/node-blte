/*!
	BLTEReader (https://github.com/Kruithne/node-blte)
	Author: Kruithne <kruithne@gmail.com>
	License: MIT
 */

const Bufo = require('bufo');
const md5 = require('md5');
const zlib = require('zlib');
const util = require('util');
const salsa20 = require('node-salsa20');
const bytey = require('bytey');

const ENC_TYPE_SALSA20 = 0x53;
const ENC_TYPE_ARC4 = 0x41;
const EMPTY_HASH = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
const KEY_RING = {};

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
			BLTEReader.error('Not enough data. (8)');

		let magic = buffer.readInt32();
		if (magic !== 0x45544c42)
			BLTEReader.error('Invalid data (magic).');

		let headerSize = buffer.readInt32(1, Bufo.ENDIAN_BIG);

		let origPos = buffer.offset;
		buffer.seek(0);

		let newHash = md5(headerSize > 0 ? buffer.readUInt8(headerSize) : buffer.readUInt8(size));
		if (newHash !== hash)
			BLTEReader.error('Hash mismatch. Expected %s, got %s.', hash, newHash);

		buffer.seek(origPos);

		let numBlocks = 1;
		if (headerSize > 0) {
			if (size < 12)
				BLTEReader.error('Not enough data (12)');

			let fcBytes = buffer.readUInt8(4);

			numBlocks = fcBytes[1] << 16 | fcBytes[2] << 8 | fcBytes[3] << 0;

			if (fcBytes[0] !== 0x0F || numBlocks === 0)
				BLTEReader.error('Invalid table format.');

			let frameHeaderSize = 24 * numBlocks + 12;
			if (headerSize !== frameHeaderSize)
				BLTEReader.error('Invalid header size.');

			if (size < frameHeaderSize)
				BLTEReader.error('Not enough data (frameHeader)');
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

		this._buffer = Buffer.alloc(allocSize);
		this._processBlock();
	}

	_read(func, size, count) {
		count = count || 1;
		while (this.offset + (size * count) > this.lastWriteOffset)
			this._processBlock();

		return super._read(func, size, count);
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
				BLTEReader.error('Block data hash mismatch.');
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
				BLTEReader.error('No frame decoder implemented.');
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
			let newBuffer = Bufo.create((this.byteLength - expectedSize) + decompressed.byteLength);
			newBuffer.writeBuffer(this);
			this._buffer = newBuffer.raw;
		}
		this.writeBuffer(decompressed);
	}

	static _decryptBlock(data, index) {
		let keyNameSize = data.readUInt8();

		if (keyNameSize === 0 || keyNameSize !== 8)
			BLTEReader.error('Unexpected keyNameSize => ' + keyNameSize);

		let keyNameBytes = bytey.byteArrayToHexString(data.readUInt8(keyNameSize));
		let ivSize = data.readUInt8();

		if (ivSize !== 4)
			BLTEReader.error('Unexpected ivSize => ' + ivSize);

		let ivShort = data.readUInt8(ivSize);
		if (data.byteLength <= data.offset)
			BLTEReader.error('Unexpected EoS before encryption flag.');

		let encryptType = data.readUInt8();
		if (encryptType !== ENC_TYPE_SALSA20 && encryptType !== ENC_TYPE_ARC4)
			BLTEReader.error('Unexpected encryption type %s', encryptType);

		for (let shift = 0, i = 0; i < 4; shift += 8, i++)
			ivShort[i] ^= (index >> shift) & 0xFF;

		let key = KEY_RING[keyNameBytes];
		if (key === undefined)
			BLTEReader.error('Unknown key %s', keyNameBytes);

		if (encryptType === ENC_TYPE_ARC4)
			BLTEReader.error('Arc4 decryption not implemented.');

		let keyBuffer = Bufo.create(key.length + 8);
		for (let i = 0; i < 8; i++)
			keyBuffer.writeUInt8(i < ivShort.length ? ivShort[i] : 0x0);

		keyBuffer.writeUInt8(key);

		let instance = salsa20(20).key(keyBuffer.buffer);
		return Bufo.create(instance.decrypt(data.readBuffer()));
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
				throw new Error('Encryption keys are expected to be 8-bytes (16 length string).');

			// Store in static key ring.
			KEY_RING[keyName] = keys[keyName];
		}
	}

	static error(message, ...args) {
		throw new Error(util.format('BLTEReader: ' + message, ...args));
	}
}

module.exports = BLTEReader;