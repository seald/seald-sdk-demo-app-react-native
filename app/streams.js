import { Readable as NodeReadable, Writable as NodeWritable } from 'readable-stream'
import * as RNFS from 'react-native-fs'
import { Buffer } from '@craftzdog/react-native-buffer'
import { toByteArray } from 'react-native-quick-base64'

export const readFileStream = (filePath) => {
  let position = 0
  return new NodeReadable({
    highWaterMark: 262144,
    async read (size) {
      try {
        if (size > 0) { // workaround bug on RNFS that, on certain platforms, reads the whole file when size is 0
          const b64 = await RNFS.read(filePath, size, position, 'base64')
          if (b64.length === 0) {
            this.push(null) // Signal the end of the stream
            return
          }
          const uint8buff = toByteArray(b64) // manually using `react-native-quick-base64` is ~15x faster than using `Buffer.from(x, 'base64')`
          const buff = Buffer.from(uint8buff)
          this.push(buff)
          position += buff.length
        } else {
          this.push(Buffer.alloc(0))
        }
      } catch (e) {
        this.emit('error')
      }
    }
  })
}

export const writeFileStream = (filePath) => {
  return new NodeWritable({
    highWaterMark: 262144,
    write (chunk, _, callback) {
      RNFS.appendFile(filePath, chunk.toString('base64'), 'base64')
        .then(() => {
          callback()
        })
        .catch(err => callback(err))
    },
    final (callback) {
      this.emit('end')
      callback()
    }
  })
}
