// A test fixture (not part of the build): a lab whose file throws WHILE IT LOADS, as a lab with a mistake at
// its top level would. The registry must leave it out, say why, and load every other lab.
throw new Error("this lab is broken on purpose");

export {};
