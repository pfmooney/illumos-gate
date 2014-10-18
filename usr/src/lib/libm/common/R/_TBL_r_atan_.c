/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Table of constants for r_atan_().
 * By K.C. Ng, March 9, 1989
 */

#include "libm.h"

const float _TBL_r_atan_hi[] = {
	4.636476040e-01, 4.883339405e-01, 5.123894811e-01, 5.358112454e-01,
	5.585992932e-01, 5.807563663e-01, 6.022873521e-01, 6.231993437e-01,
	6.435011029e-01, 6.632030010e-01, 6.823165417e-01, 7.008544207e-01,
	7.188299894e-01, 7.362574339e-01, 7.531512976e-01, 7.695264816e-01,
	7.853981853e-01, 8.156919479e-01, 8.441540003e-01, 8.709034324e-01,
	8.960554004e-01, 9.197195768e-01, 9.420000315e-01, 9.629943371e-01,
	9.827937484e-01, 1.001483083e+00, 1.019141316e+00, 1.035841227e+00,
	1.051650167e+00, 1.066630363e+00, 1.080839038e+00, 1.094328880e+00,
	1.107148767e+00, 1.130953789e+00, 1.152572036e+00, 1.172273874e+00,
	1.190289974e+00, 1.206817389e+00, 1.222025275e+00, 1.236059427e+00,
	1.249045730e+00, 1.261093378e+00, 1.272297382e+00, 1.282740831e+00,
	1.292496681e+00, 1.301628828e+00, 1.310193896e+00, 1.318242073e+00,
	1.325817704e+00, 1.339705706e+00, 1.352127433e+00, 1.363300085e+00,
	1.373400807e+00, 1.382574797e+00, 1.390942812e+00, 1.398605466e+00,
	1.405647635e+00, 1.412141085e+00, 1.418146968e+00, 1.423717976e+00,
	1.428899288e+00, 1.433730125e+00, 1.438244820e+00, 1.442473054e+00,
	1.446441293e+00,
};

const float _TBL_r_atan_lo[] = {
	+5.012158688e-09, +1.055042365e-08, -2.075691974e-08, -7.480973174e-09,
	+2.211159789e-08, -1.268522887e-08, -5.950149262e-09, -1.374726910e-08,
	+5.868937336e-09, -8.316245470e-09, +1.320299514e-08, -1.277747597e-08,
	+1.018833551e-08, -4.909868068e-09, -1.660708016e-08, -1.222759671e-09,
	-2.185569414e-08, -2.462078896e-08, -1.416911655e-08, +2.470642002e-08,
	-1.580020736e-08, +2.851478520e-08, +8.908211058e-09, -6.400973085e-09,
	-2.513142405e-08, +5.292293181e-08, +2.785247055e-08, +2.643104224e-08,
	+4.603683834e-08, +1.851388043e-09, -3.735403453e-08, +2.701113111e-08,
	-4.872354964e-08, -4.477816518e-08, -3.857382325e-08, +6.845639611e-09,
	-2.453011483e-08, -1.824929363e-08, +4.798058129e-08, +6.221672777e-08,
	+4.276110843e-08, +4.185424007e-09, +1.285398099e-08, +4.836914869e-08,
	-1.342359379e-08, +5.960489879e-09, +3.875391386e-08, -2.204224536e-08,
	-4.053271141e-08, -4.604370218e-08, -5.190222652e-08, +1.529194549e-08,
	-4.043566193e-08, +2.481348993e-08, +1.503647518e-08, +4.638297924e-08,
	+1.392036975e-08, -2.006252586e-08, +3.051175312e-08, -4.209960824e-09,
	-1.598675681e-08, +2.705746205e-08, -2.514289044e-08, +4.517691110e-08,
	+3.948537852e-08,
};
