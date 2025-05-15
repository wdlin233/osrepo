type StrideInner = usize;
#[derive(Default, Clone, Copy)]
pub struct Stride(StrideInner);

impl Stride {
    const BIG_STRIDE: StrideInner = StrideInner::MAX / 10000;

    pub fn step(&mut self, prio: usize) {
        let pass = Stride::BIG_STRIDE / prio;
        self.0 += pass;
    }
}

impl PartialOrd for Stride {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.0 == other.0 {
            Some(core::cmp::Ordering::Equal)
        } else if self.0 < other.0 {
            Some(core::cmp::Ordering::Less)
        } else {
            Some(core::cmp::Ordering::Greater)
        }
    }
}

impl Ord for Stride {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialEq for Stride {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl Eq for Stride {}