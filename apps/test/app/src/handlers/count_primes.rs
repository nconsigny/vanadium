use alloc::{vec, vec::Vec};

fn count_primes(n: u32) -> u32 {
    if n < 2 {
        return 0;
    }

    let mut is_prime = vec![true; (n + 1) as usize];
    is_prime[0] = false;
    is_prime[1] = false;

    let mut i = 2;
    let mut square = 4;
    loop {
        if square > n {
            break;
        }
        if is_prime[i as usize] {
            let mut multiple = i * i;
            while multiple <= n {
                is_prime[multiple as usize] = false;
                multiple += i;
            }
        }
        square += 2 * i + 1;
        i += 1;
    }

    // Count the primes
    is_prime.iter().filter(|&&p| p).count() as u32
}

pub fn handle_count_primes(data: &[u8]) -> Vec<u8> {
    if data.len() != 4 {
        return vec![];
    }
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let count = count_primes(n);
    count.to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_count_primes() {
        assert_eq!(super::count_primes(0), 0);
        assert_eq!(super::count_primes(1), 0);
        assert_eq!(super::count_primes(2), 1);
        assert_eq!(super::count_primes(3), 2);
        assert_eq!(super::count_primes(4), 2);
        assert_eq!(super::count_primes(5), 3);
        assert_eq!(super::count_primes(10000), 1229);
    }
}
