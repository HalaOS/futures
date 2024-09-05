use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use cooked_waker::{IntoWaker, WakeRef};
use futures::{future::BoxFuture, FutureExt, Stream};

struct RawFutureWaitMap<K, R> {
    futs: HashMap<K, BoxFuture<'static, R>>,
    ready_queue: VecDeque<K>,
    waker: Option<Waker>,
}

impl<K, R> Default for RawFutureWaitMap<K, R> {
    fn default() -> Self {
        Self {
            futs: HashMap::new(),
            ready_queue: VecDeque::new(),
            waker: None,
        }
    }
}

/// A waitable map for futures.
pub struct FuturesUnorderedMap<K, R> {
    inner: Arc<Mutex<RawFutureWaitMap<K, R>>>,
}

impl<K, R> Clone for FuturesUnorderedMap<K, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<K, R> AsRef<FuturesUnorderedMap<K, R>> for FuturesUnorderedMap<K, R> {
    fn as_ref(&self) -> &FuturesUnorderedMap<K, R> {
        self
    }
}

impl<K, R> FuturesUnorderedMap<K, R> {
    /// Create a new future `WaitMap` instance.
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }
    /// Insert a new key / future pair.
    pub fn insert<Fut>(&self, k: K, fut: Fut)
    where
        Fut: Future<Output = R> + Send + 'static,
        K: Hash + Eq + Clone,
    {
        let mut inner = self.inner.lock().unwrap();

        inner.ready_queue.push_back(k.clone());
        inner.futs.insert(k, Box::pin(fut));
        let waker = inner.waker.take();

        drop(inner);

        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub fn poll_next(&self, cx: &mut Context<'_>) -> Poll<(K, R)>
    where
        K: Hash + Eq + Clone + Send + Sync + 'static + Debug,
        R: 'static,
    {
        let mut inner = self.inner.lock().unwrap();

        inner.waker = Some(cx.waker().clone());

        while let Some(key) = inner.ready_queue.pop_front() {
            let mut fut = match inner.futs.remove(&key) {
                Some(fut) => fut,
                None => continue,
            };

            drop(inner);

            let waker = Arc::new(FutureWaitMapWaker(key.clone(), self.inner.clone())).into_waker();

            let mut proxy_context = Context::from_waker(&waker);

            match fut.poll_unpin(&mut proxy_context) {
                Poll::Ready(r) => {
                    return Poll::Ready((key, r));
                }
                _ => {
                    inner = self.inner.lock().unwrap();
                    inner.futs.insert(key, fut);
                }
            }
        }

        Poll::Pending
    }
}

impl<K, R> Stream for FuturesUnorderedMap<K, R>
where
    K: Hash + Eq + Clone + Send + Sync + 'static + Debug,
    R: 'static,
{
    type Item = (K, R);

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        FuturesUnorderedMap::poll_next(&self, cx).map(Some)
    }
}

impl<K, R> Stream for &FuturesUnorderedMap<K, R>
where
    K: Hash + Eq + Clone + Send + Sync + 'static + Debug,
    R: 'static,
{
    type Item = (K, R);

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        FuturesUnorderedMap::poll_next(&self, cx).map(Some)
    }
}

struct FutureWaitMapWaker<K, R>(K, Arc<Mutex<RawFutureWaitMap<K, R>>>);

impl<K, R> WakeRef for FutureWaitMapWaker<K, R>
where
    K: Hash + Eq + Clone + Debug,
{
    fn wake_by_ref(&self) {
        let mut inner = self.1.lock().unwrap();

        inner.ready_queue.push_back(self.0.clone());

        let waker = inner.waker.take();

        drop(inner);

        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use futures::{
        future::{pending, poll_fn},
        poll, StreamExt,
    };

    use super::FuturesUnorderedMap;

    #[futures_test::test]
    async fn test_map() {
        let map = FuturesUnorderedMap::new();

        map.insert(1, pending::<i32>());

        let mut map_ref = &map;

        let mut next = map_ref.next();

        assert_eq!(poll!(&mut next), Poll::Pending);

        map.insert(1, poll_fn(|_| Poll::Ready(2)));

        assert_eq!(poll!(&mut next), Poll::Ready(Some((1, 2))));
    }
}
