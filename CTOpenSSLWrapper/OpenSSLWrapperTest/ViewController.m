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
    //[PGPArmorHelper extractPacketsFromBytes:[PGPArmorHelper removeArmorFromKeyFile:[[NSBundle mainBundle] URLForResource:@"publicTestKey" withExtension:@"asc"]]];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
