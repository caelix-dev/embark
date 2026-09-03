//! The build-time encoder's thread budget.
//!
//! Compression runs once, on the machine doing the build, inside a proc
//! macro. Decompression runs in every consumer's shipped binary, and never
//! reaches this module. So the encoder is free to use every core the build
//! machine has, and the only real question is how to divide them between
//! work that nests: one derive compresses many files, each file may try
//! several codecs, and one codec may split its input into blocks.
//!
//! A single budget answers that. Each level asks for as many extra workers
//! as it has independent work, takes whatever is left, and hands them back
//! when it is done, so the three levels together never oversubscribe.

#[cfg(all(feature = "enc", feature = "parallel-encode"))]
mod imp {
    extern crate std;

    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{OnceLock, mpsc};

    /// Threads the encoder may use in total, the calling thread included.
    ///
    /// `EMBARK_ENCODE_THREADS` overrides the machine's parallelism, which is
    /// what a build under an external job server needs: cargo already runs
    /// several rustc processes, and each one of them expanding a macro that
    /// grabs every core is how a build machine ends up thrashing. Setting it
    /// to `1` turns the encoder back into a single-threaded one.
    fn workers() -> usize {
        static WORKERS: OnceLock<usize> = OnceLock::new();
        *WORKERS.get_or_init(|| {
            let asked = std::env::var("EMBARK_ENCODE_THREADS")
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok());
            match asked {
                Some(n) if n > 0 => n,
                _ => std::thread::available_parallelism().map_or(1, |n| n.get()),
            }
        })
    }

    /// Workers not currently claimed by an outer level.
    fn spare() -> &'static AtomicUsize {
        static SPARE: OnceLock<AtomicUsize> = OnceLock::new();
        SPARE.get_or_init(|| AtomicUsize::new(workers() - 1))
    }

    /// Claim up to `want` extra workers, returning how many were granted.
    fn reserve(want: usize) -> usize {
        let spare = spare();
        let mut free = spare.load(Ordering::Relaxed);
        loop {
            let take = want.min(free);
            if take == 0 {
                return 0;
            }
            match spare.compare_exchange_weak(
                free,
                free - take,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return take,
                Err(now) => free = now,
            }
        }
    }

    fn claim(next: &AtomicUsize, len: usize) -> Option<usize> {
        let index = next.fetch_add(1, Ordering::Relaxed);
        (index < len).then_some(index)
    }

    /// Apply `f` to every item, in parallel where the budget allows.
    ///
    /// Results come back in the order of `items` however the work was
    /// scheduled, so nothing a caller decides from them -- which codec was
    /// smallest, which entry goes where in a manifest -- can depend on how
    /// many threads the build machine happened to offer.
    ///
    /// Items are claimed one at a time rather than dealt out up front:
    /// assets differ in size by orders of magnitude, and a static split
    /// leaves one worker holding the only large file while the rest idle.
    pub(crate) fn map<T, R, F>(items: &[T], f: F) -> Vec<R>
    where
        T: Sync,
        R: Send,
        F: Fn(&T) -> R + Sync,
    {
        let len = items.len();
        let extra = if len < 2 { 0 } else { reserve(len - 1) };
        if extra == 0 {
            return items.iter().map(f).collect();
        }

        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..extra {
                let tx = tx.clone();
                let (next, f) = (&next, &f);
                scope.spawn(move || {
                    while let Some(index) = claim(next, len) {
                        // The receiver outlives the scope, so a send here
                        // cannot fail.
                        let _ = tx.send((index, f(&items[index])));
                    }
                });
            }
            // The calling thread is one of the workers, not an idle
            // supervisor; its own sender has to go before the channel can
            // close.
            while let Some(index) = claim(&next, len) {
                let _ = tx.send((index, f(&items[index])));
            }
            drop(tx);
        });
        spare().fetch_add(extra, Ordering::Relaxed);

        let mut slots: Vec<Option<R>> = (0..len).map(|_| None).collect();
        for (index, value) in rx {
            slots[index] = Some(value);
        }
        slots
            .into_iter()
            .map(|slot| slot.expect("every index was claimed exactly once"))
            .collect()
    }
}

#[cfg(not(all(feature = "enc", feature = "parallel-encode")))]
mod imp {
    use alloc::vec::Vec;

    pub(crate) fn map<T, R, F>(items: &[T], f: F) -> Vec<R>
    where
        T: Sync,
        R: Send,
        F: Fn(&T) -> R + Sync,
    {
        items.iter().map(f).collect()
    }
}

pub(crate) use imp::map;
