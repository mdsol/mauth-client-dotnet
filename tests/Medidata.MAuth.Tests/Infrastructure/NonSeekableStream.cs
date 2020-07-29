using System;
using System.IO;

namespace Medidata.MAuth.Tests.Infrastructure
{
    internal class NonSeekableStream: Stream
    {
        private readonly Stream _baseStream;


        public override bool CanSeek => false;

        public override bool CanRead => _baseStream.CanRead;

        public override bool CanWrite => _baseStream.CanWrite;

        public override long Length => _baseStream.Length;

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public NonSeekableStream(Stream baseStream) => _baseStream = baseStream;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void Flush() => _baseStream.Flush();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => _baseStream.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => _baseStream.Write(buffer, offset, count);
    }
}
