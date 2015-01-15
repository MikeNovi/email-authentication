#uts File.dirname(__FILE__)
require File.dirname(__FILE__) + '/test_helper.rb' 


class EmailSMTPAuthenticationTest <  Minitest::Test

  def setup
    @f=EmailAuthentication::Base.new
    @authentic = 'scott.sproule@ficonab.com'
    @from = 'scott.sproule@estormtech.com'
    @authentic2 = 'info2@paulaner.com.sg'
    @not_authentic = 'sassafras_jones@michaelnovi.com'
    @blocked = 'sassafras_jones@odney.com'
    
  end
  
  def test_google_mx
    @f.set_address(@authentic, @from)
    success,msg= @f.check(@authentic, @from)
    assert_equal success, EmailAuthentication::VALID
    puts msg
  end
  
  def test_smtp_mx
    success,msg= @f.check(@authentic2, @from)
    # uncomment this if not on travis as travis seems to block the port
    assert_equal success, EmailAuthentication::VALID
    puts msg
  end
 
  def test_smtp_mx_blocked
    success,msg= @f.check(@blocked, @from)
    assert_equal success, EmailAuthentication::BLOCKED
    puts msg
  end

  def test_smtp_mx_not_authentic
    success,msg= @f.check(@not_authentic, @from)
    assert_equal success, EmailAuthentication::NOT_VALID
    puts msg
  end
end