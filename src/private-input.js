'use strict';

const fs = require('node:fs');
const { TextDecoder } = require('node:util');

const MAX_ADMIN_TOKEN_BYTES = 16 * 1024;
const MAX_LICENSE_REQUEST_BYTES = 64 * 1024;
const READ_BUFFER_BYTES = 4096;

class PrivateInputError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PrivateInputError';
    this.code = code;
  }
}

function stripOneTransportLineEnding(bytes) {
  let end = bytes.length;
  if (end > 0 && bytes[end - 1] === 0x0a) {
    end -= 1;
    if (end > 0 && bytes[end - 1] === 0x0d) end -= 1;
  }
  return bytes.subarray(0, end);
}

function decodePrivateBytes(bytes, { label, maximum, stripLineEnding = true }) {
  try {
    const logical = stripLineEnding ? stripOneTransportLineEnding(bytes) : bytes;
    if (logical.length === 0) {
      throw new PrivateInputError('PRIVATE_INPUT_EMPTY', `${label} input is empty.`);
    }
    if (logical.length > maximum) {
      throw new PrivateInputError('PRIVATE_INPUT_TOO_LARGE', `${label} input exceeds the size limit.`);
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(logical);
    } catch (error) {
      if (error instanceof PrivateInputError) throw error;
      throw new PrivateInputError(
        'PRIVATE_INPUT_ENCODING',
        `${label} input must be strict UTF-8.`,
      );
    }
  } finally {
    bytes.fill(0);
  }
}

function readBoundedFd(fd, { label, maximum }) {
  const chunks = [];
  const buffer = Buffer.allocUnsafe(READ_BUFFER_BYTES);
  let total = 0;
  let exceeded = false;
  try {
    while (true) {
      const count = fs.readSync(fd, buffer, 0, buffer.length);
      if (count === 0) break;
      if (exceeded || total + count > maximum + 2) {
        exceeded = true;
        continue;
      }
      total += count;
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    if (exceeded) {
      throw new PrivateInputError('PRIVATE_INPUT_TOO_LARGE', `${label} input exceeds the size limit.`);
    }
    return Buffer.concat(chunks, total);
  } finally {
    buffer.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

function readPrivateStdin({ label, maximum }) {
  let bytes;
  try {
    bytes = readBoundedFd(0, { label, maximum });
    return decodePrivateBytes(bytes, { label, maximum });
  } catch (error) {
    if (bytes) bytes.fill(0);
    if (error instanceof PrivateInputError) throw error;
    throw new PrivateInputError('PRIVATE_INPUT_READ', `${label} input could not be read.`);
  }
}

function readPrivateFile(filePath, { label, maximum }) {
  let fd;
  let bytes;
  try {
    const before = fs.lstatSync(filePath);
    if (!before.isFile() || before.isSymbolicLink()) {
      throw new PrivateInputError('PRIVATE_INPUT_FILE', `${label} file must be a regular file.`);
    }
    if ((before.mode & 0o077) !== 0) {
      throw new PrivateInputError(
        'PRIVATE_INPUT_PERMISSIONS',
        `${label} file must not be accessible by group or other users.`,
      );
    }
    if (before.size > maximum + 2) {
      throw new PrivateInputError('PRIVATE_INPUT_TOO_LARGE', `${label} input exceeds the size limit.`);
    }
    const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
    fd = fs.openSync(filePath, flags);
    const opened = fs.fstatSync(fd);
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    ) {
      throw new PrivateInputError('PRIVATE_INPUT_FILE_CHANGED', `${label} file changed before use.`);
    }
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== bytes.length) {
      throw new PrivateInputError('PRIVATE_INPUT_FILE_CHANGED', `${label} file changed during use.`);
    }
    return decodePrivateBytes(bytes, { label, maximum });
  } catch (error) {
    if (bytes) bytes.fill(0);
    if (error instanceof PrivateInputError) throw error;
    throw new PrivateInputError('PRIVATE_INPUT_FILE', `${label} file could not be read safely.`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

module.exports = {
  MAX_ADMIN_TOKEN_BYTES,
  MAX_LICENSE_REQUEST_BYTES,
  PrivateInputError,
  decodePrivateBytes,
  readPrivateFile,
  readPrivateStdin,
};
