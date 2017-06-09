using System;
using System.IO;

namespace Medidata.MAuth.Tests.Infrastructure
{
    internal class NonSeekableStream: Stream
    {
        private readonly Stream baseStream;


        public override bool CanSeek => false;

        public override bool CanRead => baseStream.CanRead;

        public override bool CanWrite => baseStream.CanWrite;

        public override long Length => baseStream.Length;

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public NonSeekableStream(Stream baseStream) => this.baseStream = baseStream;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void Flush() => baseStream.Flush();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => baseStream.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => baseStream.Write(buffer, offset, count);
    }
}
