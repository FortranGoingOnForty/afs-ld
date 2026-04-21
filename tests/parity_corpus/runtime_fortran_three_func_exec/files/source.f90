program main
  integer :: v
  v = add3(7)
contains
  integer function add3(x)
    integer, intent(in) :: x
    add3 = twice(x) + one()
  end function add3

  integer function twice(x)
    integer, intent(in) :: x
    twice = x + x
  end function twice

  integer function one()
    one = 8
  end function one
end program main
