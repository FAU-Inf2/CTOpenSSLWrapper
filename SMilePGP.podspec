Pod::Spec.new do |spec|
  spec.name          = 'SMilePGP'
  spec.version       = '1.3.1'
  spec.platform      = :ios, '7.0'
  spec.license       = 'MIT'
  spec.source        = { :git => 'https://github.com/FAU-Inf2/SMilePGP.git', :tag => spec.version.to_s }
  spec.source_files  = 'CTOpenSSLWrapper/CTOpenSSLWrapper/*.{h,m}', 'CTOpenSSLWrapper/CTOpenSSLWrapper/Framework Additions/**/**/*.{h,m}', 'CTOpenSSLWrapper/CTOpenSSLWrapper/**/*.{h,m}'
  spec.frameworks    = 'Foundation'
  spec.requires_arc  = true
  spec.homepage      = 'https://github.com/FAU-Inf2/SMilePGP'
  spec.summary       = 'Objc OpenSSL PGP.'
  spec.author        = { 'SMile@FAU' => 'fixmymail@i2.cs.fau.de' }
  
  spec.dependency 'Godzippa'

  spec.vendored_frameworks = 'openssl.framework'
end
