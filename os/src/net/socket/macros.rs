#[macro_export]
macro_rules! ax_err {
    ($err: ident) => {
        Err($crate::ax_err_type!($err))
    };
    ($err: ident, $msg: expr) => {
        Err($crate::ax_err_type!($err, $msg))
    };
}

#[macro_export]
macro_rules! ax_err_type {
    ($err: ident) => {{
        use $crate::net::socket::AxError::*;

        $err
    }};
    ($err: ident, $msg: expr) => {{
        use $crate::net::socket::AxError::*;
        $err
    }};
}
