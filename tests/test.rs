#[cfg(test)]
mod tests {

    use kyberlib::kyberlib;

    #[test]
    fn test_kyberlib() {
        let kyberlib = kyberlib::new();
        assert_eq!(kyberlib, kyberlib::default());
    }
}
