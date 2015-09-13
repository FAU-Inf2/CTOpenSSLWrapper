//
//  ViewController.m
//  OpenSSLWrapperTest
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "ViewController.h"
#import "PGPArmorHelper.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSURL* keyFileURL = [[NSBundle mainBundle] URLForResource:@"publicTestKey" withExtension:@"asc"];
    char* chars = [PGPArmorHelper removeArmorFromKeyFile:keyFileURL];
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)extractPacketsFromBytes:(char *)bytes {

}

- (void)extractPublicKeyFromBytes:(char *)bytes {
    
}

@end
