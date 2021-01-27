use std::io::{self, Read, Write};
use log::{debug};

use futures::{Future, Stream, Sink, Poll, Async, AsyncSink};

struct ReadHalf<R: Read> {
    reader: R,
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
}

impl<R: Read> ReadHalf<R> {
    fn as_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    fn poll<W: Write>(&mut self, writer: &mut W) -> Poll<u64, io::Error> {
        loop {
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(self.reader.read(&mut self.buf));
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            while self.pos < self.cap {
                let i = try_nb!(writer.write(&self.buf[self.pos..self.cap]));
                self.pos += i;
                self.amt += i as u64;
            }

            if self.pos == self.cap && self.read_done {
                try_nb!(writer.flush());
                return Ok(self.amt.into());
            }
        }
    }
}

pub struct Transfer<T, U>
where
    T: Read + Write,
    U: Read + Write,
{
    first: ReadHalf<T>,
    second: ReadHalf<U>,
}

pub fn transfer<T, U>(first: T, second: U) -> Transfer<T, U>
where
    T: Read + Write,
    U: Read + Write,
{
    Transfer {
        first: ReadHalf {
            reader: first,
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Box::new([0; 2024]),
        },
        second: ReadHalf {
            reader: second,
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Box::new([0; 2024]),
        },
    }
}

impl<T, U> Future for Transfer<T, U>
where
    T: Read + Write,
    U: Read + Write,
{
    type Item = (u64, u64);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(u64, u64), io::Error> {
        let first = self.first.poll(self.second.as_mut())?;
        let second = self.second.poll(self.first.as_mut())?;
        if let (Async::Ready(first), Async::Ready(second)) = (first, second) {
            Ok(Async::Ready((first, second)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

struct StreamHalf<T: Stream> {
    inner: Option<T>,
    buffered: Option<T::Item>,
    done: bool,
}

impl<T: Stream> StreamHalf<T> {
    fn poll<U: Sink<SinkItem = T::Item>, W>(&mut self, sink: &mut U) -> Poll<(), W>
    where
        W: From<T::Error> + From<U::SinkError>,
    {
        if self.done {
            return Ok(Async::Ready(()));
        }

        let stream = self.inner.as_mut().expect(
            "Attempted to poll StreamTransfer after completion",
        );

        if let Some(item) = self.buffered.take() {
            if let AsyncSink::NotReady(item) = sink.start_send(item)? {
                self.buffered = Some(item);
                return Ok(Async::NotReady);
            }
        }

        loop {
            match stream.poll()? {
                Async::Ready(Some(item)) => {
                    if let AsyncSink::NotReady(item) = sink.start_send(item)? {
                        self.buffered = Some(item);
                        return Ok(Async::NotReady);
                    }
                }
                Async::Ready(None) => {
                    try_ready!(sink.poll_complete());
                    self.done = true;
                    return Ok(Async::Ready(()));
                }
                Async::NotReady => {
                    try_ready!(sink.poll_complete());
                    return Ok(Async::NotReady);
                }
            }
        }
    }

    fn inner_mut(&mut self) -> &mut T {
        self.inner.as_mut().expect(
            "Attempted to poll StreamTransfer after completion",
        )
    }

    fn complete(&mut self) -> T {
        self.inner.take().unwrap()
    }
}

pub struct StreamTransfer<T, U, V, W>
where
    T: Sink<SinkItem = V, SinkError = W> + Stream<Item = V, Error = W>,
    U: Sink<SinkItem = V, SinkError = W> + Stream<Item = V, Error = W>,
{
    first: StreamHalf<T>,
    second: StreamHalf<U>,
}

pub fn stream_transfer<T, U, V, W>(first: T, second: U) -> StreamTransfer<T, U, V, W>
where
    T: Sink<SinkItem = V, SinkError = W> + Stream<Item = V, Error = W>,
    U: Sink<SinkItem = V, SinkError = W> + Stream<Item = V, Error = W>,
{
    StreamTransfer {
        first: StreamHalf {
            inner: Some(first),
            buffered: None,
            done: false,
        },
        second: StreamHalf {
            inner: Some(second),
            buffered: None,
            done: false,
        },
    }
}

impl<T, U, V, W> Future for StreamTransfer<T, U, V, W>
where
    T: Sink<SinkItem = V, SinkError = W>
        + Stream<Item = V, Error = W>,
    U: Sink<SinkItem = V, SinkError = W>
        + Stream<Item = V, Error = W>,
{
    type Item = (T, U);
    type Error = W;

    fn poll(&mut self) -> Poll<(T, U), W> {
        let first = self.first.poll::<_, W>(self.second.inner_mut())?;
        let second = self.second.poll::<_, W>(self.first.inner_mut())?;
        if (first, second) == (Async::Ready(()), Async::Ready(())) {
            Ok(Async::Ready(
                (self.first.complete(), self.second.complete()),
            ))
        } else {
            Ok(Async::NotReady)
        }
    }
}
